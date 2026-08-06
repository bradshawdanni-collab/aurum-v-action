FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/aurum-v/src

RUN python -m pip install --no-cache-dir cryptography==50.0.0

WORKDIR /github/workspace

COPY src /opt/aurum-v/src
COPY entrypoint.sh /opt/aurum-v/entrypoint.sh
RUN sed -i 's/\r$//' /opt/aurum-v/entrypoint.sh \
    && chmod 0555 /opt/aurum-v/entrypoint.sh

ENTRYPOINT ["bash", "/opt/aurum-v/entrypoint.sh"]
