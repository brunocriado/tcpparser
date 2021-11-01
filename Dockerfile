FROM python:3.8-alpine AS builder
WORKDIR /tcpparser
COPY ./src/tcpparser /tcpparser/bin
COPY ./requirements.txt /tmp
RUN pip3 install --target=/tcpparser/dependencies -r /tmp/requirements.txt
#RUN python3 -m pip install --index-url https://test.pypi.org/simple/ --no-deps tcpparser

FROM python:3.8-alpine 
RUN apk add iptables
WORKDIR /tcpparser
COPY --from=builder	/tcpparser .
ENV PYTHONPATH="${PYTHONPATH}:/tcpparser/dependencies"
USER root
EXPOSE 3021/tcp
WORKDIR /tcpparser/bin
CMD ["python3", "tcpparser.py"]