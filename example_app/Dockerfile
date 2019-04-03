FROM tiangolo/meinheld-gunicorn-flask:python3.7
# see: https://github.com/tiangolo/meinheld-gunicorn-flask-docker
#
RUN apt-get update
# node js 10
# see: https://websiteforstudents.com/install-the-latest-node-js-and-nmp-packages-on-ubuntu-16-04-18-04-lts/
# upgrade pip
RUN pip install -U pip

# copy over our requirements.txt file
COPY requirements.txt /tmp/
# install required python packages

RUN pip install -r /tmp/requirements.txt

# copy over our app code
COPY . /app

RUN echo "Running as $(whoami) on $(python --version)"
