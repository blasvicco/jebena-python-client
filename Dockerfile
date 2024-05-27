FROM python:3.13.0b1-alpine3.20

ENV ESSENTIAL_PACKAGES="" \
    UTILITY_PACKAGES="mlocate vim"

RUN apk update && \
    apk --no-cache --progress add $ESSENTIAL_PACKAGES $UTILITY_PACKAGES

ADD ./app/requirements.txt /tmp
RUN cd /tmp && \
    pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    rm  /tmp/requirements.txt

#ADD ./entrypoint.sh /home/entrypoint.sh
#ENTRYPOINT ["/home/entrypoint.sh"]

WORKDIR /home/app
