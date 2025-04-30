FROM ubuntu:focal AS base

# --- System dependencies ---
RUN apt-get update && apt-get install -y \
  bash \
  tmux \
  time \
  python3 \
  python3-virtualenvwrapper \
  python3-venv \
  libgomp1 \
  wget \
  gcc \
  pypy-dev

# --- Add non-privileged user ---
ARG angr_spec_user=angr-spec
ARG angr_spec_user_passwd=angr-spec
ARG angr_spec_user_uid=1000
ARG angr_spec_user_gid=1000

RUN groupadd -g $angr_spec_user_gid $angr_spec_user && \
    useradd -g $angr_spec_user -m -p $angr_spec_user_passwd -u $angr_spec_user_uid $angr_spec_user

# --- Initial working directory for user setup ---
WORKDIR /home/$angr_spec_user

# --- Copy config, scripts, and frozen angr repo ---
COPY container_setup/scripts ./.container_setup/scripts
COPY container_setup/config/bashrc ./.bashrc
COPY container_setup/config/ipython_config.py ./.ipython/profile_default/ipython_config.py
COPY angr /home/$angr_spec_user/angr

# --- Set PYTHONPATH ---
ENV PYTHONPATH="/home/$angr_spec_user/angr:${PYTHONPATH}"

# --- Fix file ownerships ---
RUN chown -R $angr_spec_user:$angr_spec_user /home/$angr_spec_user/.container_setup && \
    chown -R $angr_spec_user:$angr_spec_user /home/$angr_spec_user/.bashrc && \
    chown -R $angr_spec_user:$angr_spec_user /home/$angr_spec_user/.ipython

# --- Copy fallback entrypoint script and set permissions ---
COPY container_setup/scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# --- Switch to non-root user ---
USER $angr_spec_user

# --- Set working directory to mounted project root ---
WORKDIR /workspace

# --- Install angr via virtualenv (script handles it) ---
RUN /home/$angr_spec_user/.container_setup/scripts/install_angr.sh
# RUN /home/$angr_spec_user/.container_setup/scripts/install_pypy.sh

# --- Default entrypoint with bash fallback ---
ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
CMD []
