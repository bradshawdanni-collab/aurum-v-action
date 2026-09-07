FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/aurum-v/src

RUN python -m pip install --no-cache-dir cryptography==50.0.0

WORKDIR /github/workspace

COPY src /opt/aurum-v/src
COPY spec /opt/aurum-v/spec
COPY entrypoint.sh /opt/aurum-v/entrypoint.sh
RUN sed -i 's/\r$//' /opt/aurum-v/entrypoint.sh \
    && chmod 0444 /opt/aurum-v/spec/AURUMV_RECOVERY_SPECIFICATION_FROZEN.txt \
    && chmod 0555 /opt/aurum-v/entrypoint.sh

ENTRYPOINT ["bash", "/opt/aurum-v/entrypoint.sh"]
