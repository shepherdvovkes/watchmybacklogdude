# **WatchMyBacklogDude: Real-Time macOS Log Analysis System**

**WatchMyBacklogDude** is a comprehensive security monitoring system for macOS that collects and analyzes system logs in real time, identifying suspicious activity, signs of attack, and misconfigurations.

## **Key Features**

* **Real-Time Analysis**: Direct connection to the macOS system log stream for instant event detection.  
* **Multi-Layered Verification**: Efficient data processing through a cascade of filters, from quick keyword checks to deep AI-driven analysis.  
* **RAG Threat Detection**: Utilizes **Sentence Transformers** and a **FAISS** vector database for lightning-fast comparison of logs against a knowledge base of known attack vectors (MITRE ATT\&CK, etc.).  
* **External API Integration**: Automatic file hash checking via **VirusTotal** and in-depth analysis of ambiguous logs using **OpenAI**.  
* **Interactive Web UI**: A modern dashboard for visualizing detected threats, color-coded by severity level, with detailed information for each incident.  
* **Comprehensive Monitoring**: Built-in **Prometheus \+ Grafana** stack for collecting and visualizing application performance metrics.  
* **Containerization**: Fully packaged in **Docker**, enabling a simple and quick setup of the entire stack with a single command.

## **Architecture**

The system consists of several interacting components that provide a full cycle of data collection, analysis, and presentation.

![][image1]

## **Tech Stack**

| Component | Technology |
| :---- | :---- |
| **Backend** | Python 3.11, FastAPI |
| **AI/ML** | Sentence-Transformers, Faiss, NumPy |
| **External Services** | OpenAI API, VirusTotal API |
| **Web UI** | HTML, Tailwind CSS, JavaScript |
| **Containerization** | Docker, Docker Compose |
| **Monitoring** | Prometheus, Grafana |

## **Installation and Setup**

### **Prerequisites**

1. **Docker Desktop**: Installed and running on your Mac.  
2. **Python 3.11**: **Strongly recommended.** PyTorch (an AI model dependency) may have issues with newer Python versions.  
3. **API Keys**: Obtain API keys from [VirusTotal](https://www.virustotal.com/gui/join-us) and [OpenAI](https://platform.openai.com/account/api-keys).

### **Step 1: Project Setup**

1. Clone the repository:  
   git clone https://github.com/shepherdvovkes/watchmybacklogdude.git  
   cd watchmybacklogdude

2. Create and populate the .env file with your API keys. You can copy the example file:  
   cp .env.example .env  
   \# Now, edit the .env file and insert your keys

### **Step 2: Create Attack Vector Database (One-time setup)**

This step compiles our knowledge base of attacks into a fast, searchable format.

1. Create and activate a virtual environment. **Using conda is highly recommended** as it handles the PyTorch installation better.  
   * **Install and set up conda:**  
     \# Install Miniconda via Homebrew  
     brew install miniconda  
     \# Set up conda for your shell (e.g., zsh or fish)  
     conda init zsh \# or conda init fish  
     \# COMPLETELY RESTART YOUR TERMINAL

   * **Create and activate the environment:**  
     conda create \-n watchmybacklog python=3.11  
     conda activate watchmybacklog

2. Install dependencies:  
   \# First, install PyTorch via conda  
   conda install pytorch torchvision torchaudio \-c pytorch  
   \# Then, install the remaining packages via pip  
   pip install \-r requirements.txt

3. Run the script to create the vectors:  
   python create\_attack\_vectors.py

   Files attack\_vectors.index and attack\_patterns.txt should now be present in the data/ directory.

### **Step 3: Run the System**

Launch all services using Docker Compose. Note the use of docker compose (with a space).  
docker compose up \--build

* The \--build flag is necessary on the first run or after making code changes.  
* The application will start collecting and analyzing logs immediately after launch.

### **Step 4: Accessing Services**

* **Security Dashboard**: [http://localhost:8080](http://localhost:8080)  
* **Prometheus**: [http://localhost:4200](http://localhost:4200)  
* **Grafana**: [http://localhost:4201](http://localhost:4201) (default login: admin/admin)

## **Configuration**

All configuration parameters are located in the .env file:

* OPENAI\_API\_KEY: Your API key for OpenAI. Used to analyze logs that do not match known patterns.  
* VIRUSTOTAL\_API\_KEY: Your API key for VirusTotal. Used to check files found in the logs.

## **Contributing**

We welcome any contributions to the project\! If you'd like to help, please follow these steps:

1. Fork the repository.  
2. Create a new branch for your feature (git checkout \-b feature/AmazingFeature).  
3. Make your changes and commit them (git commit \-m 'Add some AmazingFeature').  
4. Push your changes to your fork (git push origin feature/AmazingFeature).  
5. Create a Pull Request.

## **License**

This project is distributed under the MIT License. See LICENSE for more information.
