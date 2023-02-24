FROM pandare/panda

COPY ./dev /addon
COPY ./.panda /root/.panda
RUN mkdir /replay
RUN mkdir /payload

RUN pip3 install scipy
RUN pip3 install pefile

CMD ["python3", "/addon/main.py"]