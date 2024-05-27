'''Jeneba API client'''

# General imports
import json
import logging
import socket
import ssl
import time

from http.client import RemoteDisconnected
from json.decoder import JSONDecodeError
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import urlopen, Request

# Constant
__LOGGER = None
__RETRY_DELAY = 5
__RETRY_DELAY_FACTOR = 3
__VERSION__ = "1.0.0"

MAX_RUN_TIME_IN_SECONDS = 60 * 5
MESSAGES = {
	# Jebena messages
	'JENEBA_401': 'Invalid or disabled Jebena API Key {} for endpoint {} (HTTP 401 Unauthorized).\n',
	'JENEBA_502_503': 'Jebena API Server {} returned an HTTP {} response\n*** Server Response:\n{}',
	'JENEBA_CONNECTION_ERROR': 'Remote Disconnected Exception.',
	'JEBENA_GQL_ERRORS': 'GQL errors encountered:\n{}',
	'JEBENA_INVALID_INPUT': 'Invalid input (unable to create JSON).',
	'JEBENA_INVALID_RESPONSE': 'Invalid response from {} (Jebena Trace ID: {}).\n{}',
	'JEBENA_INVALID_GQL_RESPONSE': 'Invalid GQL response from {} (Jebena Trace ID: {}).\nUnable to parse:\n{}...',
	'JEBENA_INVALID_SCHEMA': 'Invalid API schema endpoint.',
	'JEBENA_MISSING_TRAILING_SLASH': 'JEBENA_API_ENDPOINT missing trailing slash.',
	'JEBENA_MISSING_VARIABLES': '''
		Error: missing JEBENA variables.\n
		Make sure that your Jebena API keys are defined in your shell:\n
			export JEBENA_API_KEY_NAME=jeb00000...\n
			export JEBENA_API_SECRET_KEY=<sensitive>\n
			export JEBENA_API_ENDPOINT=https://api-hostname.example.com/v1/\n
		or passed as arguments to the constructor.\n\n
		Reminder: never store your API keys under dot-files like ~/.profile.\n
		Instead, store keys in an encrypted disk image or volume,\n
		and then in your active shell, run 'source /path/to/secure-keys.env'.
	''',
	'JENEBA_RATE_LIMIT': 'Jebena API Server {} has rate-limited the request.',
	'JENEBA_SOCKET_TIMEOUT': 'Socket Timeout error.',
	'JEBENA_UNABLE_TO_FIND_ENDPOINT': 'Unable to find Jebena API Server at endpoint.',
	'JENEBA_UNKNOW_HTTP_ERROR': '''
		The Jebena API Server at {} has returned an unknown error (HTTP code: {})\n
		Response body:\n{}
	''',
	'JENEBA_UNKNOW_ERROR': 'Unknown client issue when connection to Jebena API Server.',
	'JENEBA_URL_ERROR': '''
		URL Error.\n
		Check that the network is accessible and that he hostname is correct in Jebena API Server endpoint '{}.'\n
		Error:\n{}
	''',
}

class JebenaException(Exception):
	'''Jeneba general exceptions'''
	def __init__(self, message):
		'''contructor'''
		super().__init__(message)

class JebenaGQLException(JebenaException):
	'''Raised when the server response indicates a bad query. GQL-specific error.'''

class JebenaGQLPermissionDenied(JebenaException):
	'''Raised when the user does not have sufficient server permissions for the query.'''

class JebenaInvalidEndpointException(JebenaException):
	'''Raise when there is a detected error with the endpoint argument.'''

class JebenaInvalidInputException(JebenaException):
	'''Raise when input cannot be parse to JSON.'''

class JebenaInvalidResponseException(JebenaException):
	'''Raise when response cannot be parse.'''

class JebenaMissingKeyException(JebenaException):
	'''Raised when client credentials are missing or the user is invalid.'''

class Jebena(): #pylint: disable=too-many-instance-attributes
	'''Jebena API wrapper class'''
	# Private attributes
	__last_query_id = None
	__last_query_dict = None

	def __init__(self, args, options=None):
		'''constructor'''
		Jebena.__check_required_arguments(args)

		self.is_api_endpoint_public = False
		self.__check_malformed_api_endpoint(args)
		self.endpoint = f'{args.api_endpoint}gql/'
		self.extra_delay = 0
		self.headers = {
			'Accept': 'application/json',
			'Authorization':  f'ApiKey {args.api_key_name}/{args.api_secret_key}',
			'Content-Type': 'application/json',
			'User-Agent': f'jebena-cli-tool/{__VERSION__}',
		}
		self.key_name = args.api_key_name
		self.opts = options if isinstance(options, dict) else {
			'max_run_time_in_seconds': MAX_RUN_TIME_IN_SECONDS,
		}
		self.opts['retries_allowed'] = self.opts.get('retries_allowed') or 2
		self.logger = Jebena.__get_logger()

	def execute(self, query, operation_name=None, variables=None):
		'''request jebena to execute the query'''
		wrapped = self.__parse_query(query)
		query = wrapped.get('query')
		operation_name = operation_name or wrapped.get('operationName')
		variables = variables or wrapped.get('variables')
		payload = {'query': query, 'variables': variables}
		if operation_name:
			payload['operation_name'] = operation_name
		try:
			request_payload = json.dumps(payload).encode('utf-8')
		except TypeError as error:
			raise JebenaInvalidInputException(
				f"{MESSAGES.get('JEBENA_INVALID_INPUT')}\n{error}"
			) from error

		# open request
		self.logger.debug('Request URL: %s', self.endpoint)
		self.logger.debug('Request body:\n%s\n', request_payload)
		return self.__open(query, Request(
			self.endpoint,
			data=request_payload,
			headers=self.headers,
		))

	def prettify(self, response):
		'''print the response of Jeneba API request'''
		should_return = self.opts.get('return_instead_of_raise_on_errors')
		should_return = should_return or 'error' not in response
		full_query = json.dumps(self.__last_query_dict, indent=4, sort_keys=True)
		full_response = json.dumps(response, indent=4, sort_keys=True)
		if should_return:
			return full_response
		self.logger.error(
			'GQL response includes an error. Part of the query may have succeeded.\n'
			' *** The original query was:\n%s\n\n'
			' *** The full response was:\n%s\n\n',
			full_query,
			full_response,
		)
		exception_type = JebenaGQLException
		error_messages = []
		error_index = 0
		for error in response.get('errors'):
			error_index += 1
			error_messages.append(error.get('message'))
			if error.get('errorType') == "permissionDenied":
				self.logger.error(
					" *** GQL error #%s: %s\n",
					error_index,
					error.get('message'),
				)
				exception_type = JebenaGQLPermissionDenied
		self.logger.error(
			"For GraphQL schema, see Docs tab at '%sdocs/graphiql'.",
			self.endpoint[-4],
		)
		raise exception_type(
			MESSAGES.get('JEBENA_GQL_ERRORS').format(';\n'.join(error_messages)[0:512])
		)

	# Private methods
	def __check_malformed_api_endpoint(self, args):
		'''if malformed api endpoint then raise the exception'''
		if args.api_endpoint[-1] != '/':
			raise JebenaInvalidEndpointException(
				MESSAGES.get('JEBENA_MISSING_TRAILING_SLASH')
			)
		try:
			parsed_uri = urlparse(args.api_endpoint)
			addresses = socket.getaddrinfo(parsed_uri.hostname, None)
		except Exception as error:
			raise JebenaInvalidEndpointException(
				f"{MESSAGES.get('JEBENA_UNABLE_TO_FIND_ENDPOINT')}\n'{args.api_endpoint}'\n{error}"
			) from error
		if parsed_uri.scheme not in ['http', 'https']:
			raise JebenaInvalidEndpointException(
				f"{MESSAGES.get('JEBENA_INVALID_SCHEMA')}\n'{parsed_uri.scheme}'"
			)
		self.is_api_endpoint_public = any(
			address[4][0] not in ('::1', '127.0.0.1', 'fe80::1', 'fe80::1%lo0')
			for address in addresses
		)

	def __handle_connection_error(self, error, raise_all=False):
		'''handle connection error'''
		msg = f"{MESSAGES.get('JENEBA_CONNECTION_ERROR')}\n{error}"
		self.__log_and_raise_or_retry(msg, raise_all)

	def __handle_http_error(self, error, raise_all=False):
		'''handle http error'''
		if error.code == 401:
			self.__log_and_raise(MESSAGES.get('JENEBA_401').format(
				self.key_name,
				self.endpoint,
			))
		if error.code == 429:
			self.extra_delay = 10
			msg = MESSAGES.get('JENEBA_RATE_LIMIT').format(
				self.endpoint,
			)
			self.__log_and_raise_or_retry(msg, raise_all)
			return
		# Response document may be a Jebena API Server response with info:
		response = '(Non-UTF-8 response)'
		try:
			response_data = json.loads(error.read().decode('utf-8', 'replace'))
			self.logger.critical(
				'Please file a bug report at '
				'https://github.com/jebena/jebena-python-client/issues for this:\n'
				'We should add handling for this error:\n%s',
				response_data,
			)
		except: # pylint: disable=bare-except
			pass
		response_snippet = f'{response[0:509]}...' if len(response) > 512 else response
		if error.code in [502, 503]:
			msg = MESSAGES.get('JENEBA_502_503').format(
				self.endpoint,
				error.code,
				response_snippet,
			)
			self.__log_and_raise_or_retry(msg, raise_all)
			return
		self.__log_and_raise(MESSAGES.get('JENEBA_UNKNOW_HTTP_ERROR').format(
			self.endpoint,
			error.code,
			response_snippet,
		))

	def __handle_url_error(self, error, raise_all=False):
		'''handle url error'''
		msg = MESSAGES.get('JENEBA_URL_ERROR').format(
			self.endpoint,
			error,
		)
		self.__log_and_raise_or_retry(msg, raise_all)

	def __log_and_raise(self, msg):
		'''log error and rise exception'''
		self.logger.error(msg)
		raise JebenaException(msg)

	def __log_and_raise_or_retry(self, msg, raise_all=False):
		'''log error and rise exception'''
		if raise_all:
			self.__log_and_raise(msg)
		self.logger.warning(msg)

	def __open(self, query, request):
		'''open the request to get the response'''
		is_query_a_mutation = query.split(None, 2)[0].lower() == 'mutation'
		limit_attempts = is_query_a_mutation and not self.opts.get('allow_retries_on_mutations')
		attempts_allowed = 1 if limit_attempts else 1 + self.opts.get('retries_allowed')
		attempts_tried = 0
		while attempts_tried < attempts_allowed:
			attempts_tried += 1
			raise_all = attempts_tried == attempts_allowed
			self.logger.debug(
				'Sending query: attempt %s of %s.',
				attempts_tried,
				attempts_allowed,
			)
			if attempts_tried > 1:
				# When re-attempting query, issue a warning and wait a bit before retrying:
				retry_delay = self.__calculate_delay(attempts_tried, self.extra_delay)
				if not self.opts.get('skip_logging_transient_errors'):
					self.logger.warning(
						'Jebena client failed to fetch from %s;'
						' retry in %s seconds;'
						' %s attempts left.',
						self.endpoint,
						retry_delay,
						(attempts_allowed - attempts_tried + 1), # We're after the += 1 above
					)
				time.sleep(retry_delay)
			try:
				context = ssl.SSLContext(ssl.PROTOCOL_TLS) if not self.is_api_endpoint_public else None
				self.logger.debug('Calling urlopen(...)')
				with urlopen(
					request,
					context=context,
					timeout=self.opts.get('max_run_time_in_seconds'),
				) as response:
					self.logger.debug('Finished urlopen(...)')
					self.__set_query_id(response)
					return self.__parse_response(response)
			except socket.timeout:
				msg = MESSAGES.get('JENEBA_SOCKET_TIMEOUT')
				self.__log_and_raise_or_retry(msg, raise_all)
			except RemoteDisconnected as error:
				self.__handle_connection_error(error, raise_all=raise_all)
			except HTTPError as error:
				self.__handle_http_error(error, raise_all=raise_all)
			except URLError as error:
				self.__handle_url_error(error, raise_all=raise_all)
		# We shouldn't actually ever hit this condition, based on our above try/catch code,
		# but any programming error above could lead to falling off of the edge:
		raise JebenaException(f"{MESSAGES.get('JENEBA_UNKNOW_ERROR')}\nEndpoint: {self.endpoint}.")

	def __parse_query(self, query):
		'''detect if it is a wrapped or direct query and format it accordingly'''
		self.logger.debug('Parsing wrapped query.')
		self.__last_query_dict = {
			'operationName': None,
			'query': None,
			'variables': [],
		}
		try:
			self.__last_query_dict = json.loads(query)
		except JSONDecodeError:
			self.__last_query_dict['query'] = query
		return self.__last_query_dict

	def __parse_response(self, response):
		'''try to parse the response from jebena'''
		response_string = ''
		try:
			response_string = response.read().decode('utf-8')
		except Exception as error:
			raise JebenaInvalidResponseException(
				MESSAGES.get('JEBENA_INVALID_RESPONSE').fromat(
					self.endpoint,
					self.__last_query_id,
					error,
				)
			) from error
		try:
			return json.loads(response_string)
		except JSONDecodeError as error:
			self.logger.debug('Unable to decode response string:\n%s', response_string)
			raise JebenaInvalidResponseException(
				MESSAGES.get('JEBENA_INVALID_GQL_RESPONSE').fromat(
					self.endpoint,
					self.__last_query_id,
					response_string[0:128],
				)
			) from error

	def __set_query_id(self, response):
		'''try to set the query id'''
		self.__last_query_id = None
		try:
			self.__last_query_id = response.info()['X-Log-Trace-ID']
			self.logger.debug('Jebena Trace ID: %s.', self.__last_query_id)
		except: # pylint: disable=bare-except
			pass

	# Private static methods
	@staticmethod
	def __calculate_delay(attempts_tried, extra_delay=0):
		'''rerturn the delay for next attemps based on module contants'''
		return __RETRY_DELAY + extra_delay + __RETRY_DELAY_FACTOR ** attempts_tried

	@staticmethod
	def __check_required_arguments(args):
		'''if missing required argument then raise the exception'''
		required = ['api_endpoint', 'api_key_name', 'api_secret_key']
		is_none = (getattr(args, opt) is None for opt in required)
		if any(is_none):
			raise JebenaMissingKeyException(
				MESSAGES.get('JEBENA_MISSING_VARIABLES')
			)

	@staticmethod
	def __get_logger():
		'''Return a python logger for emitting logs.'''
		global __LOGGER # pylint: disable=global-statement
		if not __LOGGER:
			__LOGGER = logging.getLogger(__name__)
		return __LOGGER
