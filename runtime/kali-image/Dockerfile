FROM kalilinux/kali-rolling@sha256:40e386ce0c263b924e59215a3a2a8d969a95d808856ed255d0b1ee95fbfec2a4

ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PYTHONDONTWRITEBYTECODE=1

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
      python3 \
      python3-pip \
      ca-certificates \
      curl \
      git \
      whatweb \
      wafw00f \
      httpx-toolkit \
      nuclei \
      sslscan \
      ffuf \
      feroxbuster \
      arjun \
      nikto \
      sqlmap \
      commix && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY bin/katana /usr/local/bin/katana
COPY bin/dalfox /usr/local/bin/dalfox

COPY tplmap /opt/tplmap

RUN chmod +x /usr/local/bin/katana /usr/local/bin/dalfox && \
    ln -sf /opt/tplmap/tplmap.py /usr/local/bin/tplmap && \
    python3 -m pip install --no-cache-dir --break-system-packages \
      schemathesis==4.24.3 && \
    python3 -m pip install --no-cache-dir --break-system-packages \
      requests==2.32.5 \
      PyYAML==6.0.3 && \
    chmod +x /opt/tplmap/tplmap.py

WORKDIR /workspace

CMD ["sleep", "infinity"]
