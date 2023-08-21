# Create alerts in The Hive from your Graylog alerts, to be turned into Hive cases.Simple Python flask app that runs as a web server, and accepts POST requests from your Graylog notifications.

# Install the required prerequisites

sudo apt install python3-pip

sudo python3 -m pip install thehive4py 

sudo python3 -m pip install Flask

sudo python3 -m pip install requests

# Move to the directory that you would like to download the folder in:

cd /opt/

# download the folder

git clone https://github.com/Graylog2TheHive/Graylog2TheHive.git 

# Move to the directory Graylog2TheHive

cd Graylog2TheHive/

# Copy graylog2thehive.service to directory /etc/systemd/system

cp graylog2thehive.service /etc/systemd/system

# Enable and start the service

sudo systemctl daemon-reload

sudo systemctl enable graylog2thehive.service

sudo systemctl start graylog2thehive.service


Credit goes to the original graylog2thehive(@ReconInfoSec) project and @H2Cyber for (most of) the code.


