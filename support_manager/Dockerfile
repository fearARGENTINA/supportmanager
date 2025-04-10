FROM python:3.9

WORKDIR /support_manager

COPY . /support_manager/

RUN apt-get update && apt-get install -y python3-dev libldap2-dev libsasl2-dev libssl-dev
RUN pip install -r requirements.txt

CMD [ "python3", "run.py"]