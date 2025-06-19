WatchMyBacklogDude: Real-Time macOS Log Analysis SystemWatchMyBacklogDude is a comprehensive security monitoring system for macOS that collects and analyzes system logs in real time, identifying suspicious activity, signs of attack, and misconfigurations.Key FeaturesReal-Time Analysis: Direct connection to the macOS system log stream for instant event detection.Multi-Layered Verification: Efficient data processing through a cascade of filters, from quick keyword checks to deep AI-driven analysis.RAG Threat Detection: Utilizes Sentence Transformers and a FAISS vector database for lightning-fast comparison of logs against a knowledge base of known attack vectors (MITRE ATT&CK, etc.).External API Integration: Automatic file hash checking via VirusTotal and in-depth analysis of ambiguous logs using OpenAI.Interactive Web UI: A modern dashboard for visualizing detected threats, color-coded by severity level, with detailed information for each incident.Comprehensive Monitoring: Built-in Prometheus + Grafana stack for collecting and visualizing application performance metrics.Containerization: Fully packaged in Docker, enabling a simple and quick setup of the entire stack with a single command.ArchitectureThe system consists of several interacting components that provide a full cycle of data collection, analysis, and presentation.graph TD
    subgraph "macOS Host"
        A[macOS Log Stream] --> B{Log Collector};
    end

    subgraph "Docker Container: WebApp"
        B -- JSON Logs --> C[FastAPI Backend];
        C -- Fast Filter --> D{Analyzer};
        D -- Suspicious Log --> E["Vectorizer (Sentence Transformer)"];
        E --> F{"Vector Search (FAISS)"};
        F -- Similarity Found --> G[Analysis: RAG];
        F -- No Similarity Found --> H[Analysis: OpenAI API];
        D -- File Path Found --> I[Analysis: VirusTotal API];
        
        subgraph "Analysis Results"
            G --> J[WebSocket];
            H --> J;
            I --> J;
        end

        J -- Real-time Data --> K[Web UI (Dashboard)];
        C -- Metrics --> L[Prometheus Endpoint];
    end

    subgraph "Docker Container: Monitoring"
        M[Prometheus] -- Metrics Collection --> L;
        N[Grafana] -- Visualization --> M;
    end

    O[User] --> K;
    O --> N;

    style A fill:#cde4ff,stroke:#6a8ebf
    style K fill:#d5f0d3,stroke:#5a9c57
    style N fill:#d5f0d3,stroke:#5a9c57
    style H fill:#ffd9c8,stroke:#c3755c
    style I fill:#ffd9c8,stroke:#c3755c

Tech Stack| Component | Technology || Backend | Python 3.11, FastAPI || AI/ML | Sentence-Transformers, Faiss, NumPy || External Services | OpenAI API, VirusTotal API || Web UI | HTML, Tailwind CSS, JavaScript || Containerization | Docker, Docker Compose || Monitoring | Prometheus, Grafana |Installation and SetupPrerequisitesDocker Desktop: Installed and running on your Mac.Python 3.11: Strongly recommended. PyTorch (an AI model dependency) may have issues with newer Python versions.API Keys: Obtain API keys from VirusTotal and OpenAI.Step 1: Project SetupClone the repository:git clone https://github.com/shepherdvovkes/watchmybacklogdude.git
cd watchmybacklogdude

Create and populate the .env file with your API keys. You can copy the example file:cp .env.example .env
# Now, edit the .env file and insert your keys

Step 2: Create Attack Vector Database (One-time setup)This step compiles our knowledge base of attacks into a fast, searchable format.Create and activate a virtual environment. Using conda is highly recommended as it handles the PyTorch installation better.Install and set up conda:# Install Miniconda via Homebrew
brew install miniconda
# Set up conda for your shell (e.g., zsh or fish)
conda init zsh # or conda init fish
# COMPLETELY RESTART YOUR TERMINAL

Create and activate the environment:conda create -n watchmybacklog python=3.11
conda activate watchmybacklog

Install dependencies:# First, install PyTorch via conda
conda install pytorch torchvision torchaudio -c pytorch
# Then, install the remaining packages via pip
pip install -r requirements.txt

Run the script to create the vectors:python create_attack_vectors.py

Files attack_vectors.index and attack_patterns.txt should now be present in the data/ directory.Step 3: Run the SystemLaunch all services using Docker Compose. Note the use of docker compose (with a space).docker compose up --build

The --build flag is necessary on the first run or after making code changes.The application will start collecting and analyzing logs immediately after launch.Step 4: Accessing ServicesSecurity Dashboard: http://localhost:8080Prometheus: http://localhost:4200Grafana: http://localhost:4201 (default login: admin/admin)ConfigurationAll configuration parameters are located in the .env file:OPENAI_API_KEY: Your API key for OpenAI. Used to analyze logs that do not match known patterns.VIRUSTOTAL_API_KEY: Your API key for VirusTotal. Used to check files found in the logs.ContributingWe welcome any contributions to the project! If you'd like to help, please follow these steps:Fork the repository.Create a new branch for your feature (git checkout -b feature/AmazingFeature).Make your changes and commit them (git commit -m 'Add some AmazingFeature').Push your changes to your fork (git push origin feature/AmazingFeature).Create a Pull Request.LicenseThis project is distributed under the MIT License. See LICENSE for more information.
