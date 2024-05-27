#!/usr/bin/env python
'''CLI command for jebena client wrapper'''

# General imports
import argparse
import os
import sys

from threading import Timer

# App imports
from client import Jebena, JebenaException, JebenaGQLException, JebenaMissingKeyException
from client import MAX_RUN_TIME_IN_SECONDS

def __exit_client(options):
	timeout = options.get('max_run_time_in_seconds')
	print(
		f'Error: Request terminated. Jebena client exceeded max run time ({timeout} seconds). '
		'This typically means the API server was unable to generate a response within a reasonable time. '
		"Check that the GQL query isn't over-fetching. It's also possible that more involved API calls may "
		'take longer than expected, in which case try temporarily increasing the timeout by setting the '
		f"ENV variable 'JEBENA_CLIENT_TIMEOUT' in your shell: export JEBENA_CLIENT_TIMEOUT={timeout * 2}"
	)
	os._exit(3) # pylint: disable=protected-access

def main():
	'''main method'''
	# Read a single query from argument -q, execute it, and print the server response to STDOUT.
	args = read_args()
	options = {
		'max_run_time_in_seconds': os.environ.get('JEBENA_CLIENT_TIMEOUT') or MAX_RUN_TIME_IN_SECONDS
	}
	watcher = Timer(
		options.get('max_run_time_in_seconds'),
		__exit_client,
		options,
	)
	try:
		# We limit runtime to prevent hangs on failed network connection or bad GQL queries:
		watcher.start()
		jebena_api = Jebena(args, options)
		response = jebena_api.execute(args.query)
		print(jebena_api.prettify(response))
	except KeyboardInterrupt:
		print('', file=sys.stderr)
		sys.exit(99)
	except JebenaMissingKeyException:
		print(
			'Jebena API Keys missing\n'
			'see https://github.com/jebena/jebena-python-client/blob/main/README.md',
			file=sys.stderr,
		)
		sys.exit(99)
	except JebenaGQLException as error:
		print(f'Jebena GQL Query Exception: {error}', file=sys.stderr)
		sys.exit(1)
	except JebenaException as error:
		print(f'Jebena GQL Client Error:  {error}', file=sys.stderr)
		sys.exit(2)
	finally:
		watcher.cancel()

def read_args():
	'''arguments for main module'''
	parser = argparse.ArgumentParser(description='Command line for jebena client.')
	parser.add_argument(
		'--api-endpoint',
		default=os.environ.get('JEBENA_API_ENDPOINT'),
		help='Jebena endpoint.',
		type=str
	)
	parser.add_argument(
		'--api-key-name',
		default=os.environ.get('JEBENA_API_KEY_NAME'),
		help='Jebena key name.',
		type=str
	)
	parser.add_argument(
		'--api-secret-key',
		default=os.environ.get('JEBENA_API_SECRET_KEY'),
		help='Jebena secret key.',
		type=str
	)
	parser.add_argument('-q', '--query', help='GQL querie.', required=True, type=str)
	return parser.parse_args()

if __name__ == "__main__":
	main()
