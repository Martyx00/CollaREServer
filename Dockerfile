FROM python:3

ENV PYTHONUNBUFFERED 1
RUN apt-get update && apt-get dist-upgrade -y

RUN mkdir -p /opt/services/flaskapp/src
RUN mkdir -p /opt/data

COPY requirements.txt /opt/services/flaskapp/src/
COPY projects.list /opt/data/
COPY users.txt /opt/data/
WORKDIR /opt/services/flaskapp/src
RUN pip install -r requirements.txt
COPY . /opt/services/flaskapp/src
EXPOSE 5090

CMD ["python", "app.py"]
