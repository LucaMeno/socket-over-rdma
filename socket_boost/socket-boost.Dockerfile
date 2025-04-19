FROM base_img

# Copy src file
#COPY . /socket_boost

WORKDIR /socket_boost

CMD ["/bin/bash", "-c", "/setup.docker.sh && tail -f /dev/null"]
