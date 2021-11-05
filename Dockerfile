FROM python:3.8-alpine
RUN apk add iptables
RUN python3 -m pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ tcpparser
USER root
EXPOSE 3021/tcp
ENTRYPOINT ["tcpparser"]
