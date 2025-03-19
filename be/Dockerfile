FROM python
RUN mkdir /BEtpp
RUN chmod 777 /BEtpp
COPY . /BEtpp
WORKDIR /BEtpp
RUN pip install -r requirements.txt
CMD ["python", "be_app.py"]