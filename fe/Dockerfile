FROM python
RUN mkdir /FEtpp
RUN chmod 777 /FEtpp
COPY . /FEtpp
WORKDIR /FEtpp
RUN pip install -r requirements.txt
CMD ["python", "fe_app.py"]