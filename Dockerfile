FROM pandare/panda

COPY ./dev /addon
COPY ./.panda /root/.panda
RUN mkdir /replay
RUN mkdir /payload

CMD ["python3", "/addon/main.py"]