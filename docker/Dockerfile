FROM pandare/panda

COPY dev /addon
COPY .panda /root/.panda
RUN mkdir /replay
RUN mkdir /payload

RUN pip3 install scipy
RUN pip3 install pefile
RUN mv /usr/local/lib/python3.8/dist-packages/pandare/data/i386-softmmu/panda/plugins/syscalls2_dso_info_windows_7_x86.so /usr/local/lib/python3.8/dist-packages/pandare/data/i386-softmmu/panda/plugins/syscalls2_dso_info_windows_7sp0_x86.so

CMD ["python3", "/addon/main.py"]