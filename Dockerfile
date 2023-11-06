FROM continuumio/miniconda3

# Install mamba for faster dependency resolution
RUN conda install mamba -y -c conda-forge

ARG conda_env=pride_env
WORKDIR /app

COPY environment.yml ./
#COPY config.ini ./
COPY *.py ./
COPY requirements.txt ./

SHELL ["/bin/bash", "-c"]
RUN mamba env create -n $conda_env -f environment.yml

RUN echo "conda activate $conda_env" >> ~/.bashrc

RUN source ~/.bashrc

# Add conda installation dir to PATH (instead of doing 'conda activate')
ENV PATH /opt/conda/envs/$conda_env/bin:$PATH

RUN pip install -r  requirements.txt

CMD [ "/bin/bash", "-c", "source ~/.bashrc && /bin/bash"]
ENTRYPOINT python main.py -c PRODUCTION
