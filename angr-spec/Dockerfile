FROM ubuntu:focal AS base

# --- System dependencies ---
RUN apt-get update
RUN apt-get install -y tmux time
RUN apt-get install -y python3 python3-virtualenvwrapper
RUN apt-get install -y libgomp1
RUN apt-get install -y wget gcc pypy-dev

# --- Add non-privileged user ---
ARG angr_spec_user=angr-spec
ARG angr_spec_user_passwd=angr-spec
ARG angr_spec_user_uid=1000
ARG angr_spec_user_gid=1000

RUN groupadd -g $angr_spec_user_gid $angr_spec_user
RUN useradd -g $angr_spec_user -m -p $angr_spec_user_passwd -u $angr_spec_user_uid $angr_spec_user

# --- Initial working directory for config setup ---
WORKDIR /home/$angr_spec_user

# --- Copy container setup (scripts & configs) ---
COPY container_setup/scripts ./.container_setup/scripts
COPY container_setup/config/bashrc ./.bashrc
COPY container_setup/config/ipython_config.py ./.ipython/profile_default/ipython_config.py
COPY angr /home/$angr_spec_user/angr

# --- Set PYTHONPATH to frozen angr clone ---
ENV PYTHONPATH="/home/$angr_spec_user/angr:${PYTHONPATH}"

# --- Fix ownership ---
RUN chown -R $angr_spec_user:$angr_spec_user /home/$angr_spec_user/.container_setup
RUN chown -R $angr_spec_user:$angr_spec_user /home/$angr_spec_user/.bashrc
RUN chown -R $angr_spec_user:$angr_spec_user /home/$angr_spec_user/.ipython

# --- Set shell and switch to user ---
RUN chsh -s /bin/bash $angr_spec_user
USER $angr_spec_user

# --- Switch working directory to mounted project ---
WORKDIR /workspace

# --- Run install scripts (from container_setup) ---
WORKDIR /workspace

# --- Run install scripts (from container_setup) ---
RUN /home/$angr_spec_user/.container_setup/scripts/install_angr.sh
#RUN /home/$angr_spec_user/.container_setup/scripts/install_pypy.sh

# --- Optional: default shell entrypoint ---
ENTRYPOINT ["/bin/bash"]

CMD ["/bin/bash", "-c", "source /home/angr-spec/.virtualenvs/angr8/bin/activate && python3 -i -c 'import angr; print(f\"angr version: {getattr(angr, \"__version__\", \"<unknown>\")}\")'"]
