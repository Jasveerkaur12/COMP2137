#!/bin/bash

# Funtion to Check Users
check_users() {
    local users=("dennis" "student" "aubrey" "captain" "snibbles" "brownie" "scooter" "sandy" "perrier" "cindy" "tiger" "yoda")

    for user in "${users[@]}"; do
        id "$user" &>/dev/null
        if [ $? -ne 0 ]; then
            echo "User $user does not exist."
            return 1
        fi
    done

    return 0
}

# Funtion to Check Firewall ports
check_firewall_ports() {
    
    local ports=("22" "80" "443" "3128")

    for port in "${ports[@]}"; do
        nc -zv 127.0.0.1 "$port" &>/dev/null
        if [ $? -ne 0 ]; then
            echo "Port $port is not open."
            return 1
        fi
    done

    return 0
}


# Funtion to Check Installed Packages
check_installed_software() {
    local software=("ufw" "openssh-server" "apache2" "squid")

    for soft in "${software[@]}"; do
        dpkg -l | grep -q "^ii\s*$soft"
        if [ $? -ne 0 ]; then
            echo "Software $soft is not installed."
            return 1
        fi
    done

    return 0
}

# Funtion to Check Network Configuration
check_network_config() {
    local ip_address="192.168.16.21/24"
    local gateway="192.168.16.1"
    local dns_server="192.168.16.1"
    local search_domains=("home.arpa" "localdomain")

    # Check IP address
    ip -br addr | grep -q " $ip_address"
    if [ $? -ne 0 ]; then
        echo "Network configuration for IP address $ip_address not found."
        return 1
    fi

    # Check gateway
    ip route | grep -q "default via $gateway"
    if [ $? -ne 0 ]; then
        echo "Gateway $gateway is not set."
        return 1
    fi

    # Check DNS server
    grep -qE "^\s*nameserver\s+$dns_server$" /etc/resolv.conf
    if [ $? -ne 0 ]; then
        echo "DNS server $dns_server is not set in /etc/resolv.conf."
        return 1
    fi

    # Check search domains
    for domain in "${search_domains[@]}"; do
        grep -qE "^\s*search\s+$domain" /etc/resolv.conf
        if [ $? -ne 0 ]; then
            echo "Search domain $domain is not set in /etc/resolv.conf."
            return 1
        fi
    done

    return 0
}

# Main function
check_configuration() {

    # Calling all fucntions if passed return 0 else 1
    check_users || return 1
    check_firewall_ports || return 1
    check_installed_software || return 1
    check_network_config || return 1

    return 0
}

# Calling the main function
check_configuration


# Function to check if a package is installed
is_installed() {
    dpkg -s "$1" &>/dev/null
}

# Function to install a package if it is not installed
install_if_not_installed() {
    if ! is_installed "$1"; then
        sudo apt-get update
        sudo apt-get install -y "$1"
    else
        echo "$1 is already installed."
    fi
}

# Check and install ufw
install_if_not_installed ufw

# Check and configure SSH server
if ! is_installed openssh-server; then
    sudo apt-get update
    sudo apt-get install -y openssh-server
    # Configure SSH to allow key authentication and disable password authentication
    sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sudo service ssh restart
else
    echo "openssh-server is already installed."
fi

# Check and install Apache2
install_if_not_installed apache2

# Check and install Squid
install_if_not_installed squid

# Configure Apache2 to listen on ports 80 and 443
sudo sed -i 's/Listen 80/Listen 80\nListen 443/' /etc/apache2/ports.conf
sudo service apache2 restart

# Configure Squid to listen on port 3128
sudo sed -i 's/http_port 3128/http_port 3128/' /etc/squid/squid.conf
sudo service squid restart

echo "Installation and configuration completed."


# Array of user accounts
users=("dennis" "student" "aubrey" "captain" "snibbles" "brownie" "scooter" "sandy" "perrier" "cindy" "tiger" "yoda")

# Function to create a user account and set up SSH keys
create_user_with_ssh_keys() {
    local username=$1
    local ssh_key_rsa="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3aasE7xXOc3n40XIU+9PAs6ccF4T7UZI0nlgB7Us9Wn6oQ2DMYb8PRzJyQqnUTc+dU1bVXwRt8n55W9rrz9Fg5GVztEPANt3yv7cJL7wZUHdVTpZxPBBmLZ26JiNbiPffNMkHN63PLwELPK6osFVR8/9mihMQYZ8S8HjA8rsgN5l2oJUw54t5ljmlkLdb7M6ZZb2u6YfoGzRtFAKnWuAY/Y0M6fVskcT4UAMMzzrqL99PxXJgwueI8UJWq6apB6qfo1uU2JFbG3A8jqTV0vtOWMnNpgNRag1fXvSEjsli6kGLeLFN6GRaGo7tMlgXg5x9MsbWc0h9MnbLrz user_rsa_key"
    local ssh_key_ed25519="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG4rT3vTt99Ox5knd4HmgTrKBT8SKzhK4rhGkEVGlCI user_ed25519_key"

    echo "Creating user account: $username"
    sudo useradd -m -s /bin/bash "$username"
    sudo mkdir -p "/home/$username/.ssh"
    sudo chown -R "$username:$username" "/home/$username/.ssh"
    echo "$ssh_key_rsa" | sudo tee -a "/home/$username/.ssh/authorized_keys"
    echo "$ssh_key_ed25519" | sudo tee -a "/home/$username/.ssh/authorized_keys"
    sudo chown "$username:$username" "/home/$username/.ssh/authorized_keys"
}

# Create each user account with SSH keys
for user in "${users[@]}"; do
    create_user_with_ssh_keys "$user"
done

# Grant sudo access to the user "dennis"
sudo usermod -aG sudo dennis

echo "User accounts created with SSH keys and sudo access (for dennis)."


# Set the hostname to 'autosrv'
echo "autosrv" > /etc/hostname
hostname -F /etc/hostname

# Get the current ethernet network interface
eth_interface=$(ip -o -4 route show to default | awk '{print $5}')

# Check if the ethernet interface is available
if [ -z "$eth_interface" ]; then
    echo "Error: Ethernet interface not found."
    exit 1
fi

# Configure the static network on the interface
cat << EOF > /etc/network/interfaces
auto lo
iface lo inet loopback

auto $eth_interface
iface $eth_interface inet static
    address 192.168.16.21
    netmask 255.255.255.0
    gateway 192.168.16.1
    dns-nameservers 192.168.16.1
    dns-search home.arpa localdomain
EOF

# Restart networking service to apply the changes
sudo systemctl restart networking

echo "Static network configuration applied to interface $eth_interface."


# Function to check if a command is available
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Function to run a script if it exists
run_script() {
  if [ -x "$1" ]; then
    echo "Running $1..."
    "$1"
  else
    echo "Script $1 not found or not executable."
  fi
}

# Individual scripts
check_install_software_script="check_install_software.sh"
ufw_firewall_setup_script="ufw_firewall_setup.sh"
server_network_setup_script="server_network_setup.sh"


# Step 1: Check and install software
run_script "$check_install_software_script"

# Step 2: Ubuntu UFW Firewall Setup 
run_script "$ufw_firewall_setup_script"

# Step 3: Ubuntu server network setup 
run_script "$server_network_setup_script"

# Step 4: Verification and applying changes
echo "Verifying system modifications..."

# For Verification

check_config="check_config.sh"
  
run_script "$check_config"


# If verification fails, re-run the scripts to apply changes
if [ $? -ne 0 ]; then
  echo "Verification failed. Reapplying changes..."

  # Re-run the individual scripts
  run_script "$check_install_software_script"
  run_script "$ufw_firewall_setup_script"
  run_script "$server_network_setup_script"

  echo "Verifying system modifications again..."
  
  # Perform verification again
  
  # Step 1: Check and install software
  run_script "$check_install_software_script"

  # Step 2: Ubuntu UFW Firewall Setup 
  run_script "$ufw_firewall_setup_script"

  # Step 3: Ubuntu server network setup 
  run_script "$server_network_setup_script"

  # Step 4: Verification and applying changes
  echo "Verifying system modifications..."

  # For Verification (again)

  check_config="check_config.sh"

  run_script "$check_config"

  # If verification still fails, display a message
  if [ $? -ne 0 ]; then
    echo "Verification still failed after reapplying changes. Manual intervention may be required."
  else
    echo "Verification passed after reapplying changes."
  fi
else
  echo "Verification passed. No further action needed."
fi
# Function to check if a UFW rule exists
ufw_rule_exists() {
    local rule=$1
    ufw status | grep -q "^$rule"
}

# Enable and start UFW if it's not already enabled
if ! ufw status | grep -q "Status: active"; then
    echo "Enabling and starting UFW..."
    sudo ufw --force enable
    echo "UFW enabled and started."
fi

# Allow SSH (port 22)
if ! ufw_rule_exists "22/tcp"; then
    echo "Allowing SSH (port 22)..."
    sudo ufw allow 22/tcp
    echo "SSH allowed."
fi

# Allow HTTP (port 80)
if ! ufw_rule_exists "80/tcp"; then
    echo "Allowing HTTP (port 80)..."
    sudo ufw allow 80/tcp
    echo "HTTP allowed."
fi

# Allow HTTPS (port 443)
if ! ufw_rule_exists "443/tcp"; then
    echo "Allowing HTTPS (port 443)..."
    sudo ufw allow 443/tcp
    echo "HTTPS allowed."
fi

# Allow Web Proxy (port 3128)
if ! ufw_rule_exists "3128/tcp"; then
    echo "Allowing Web Proxy (port 3128)..."
    sudo ufw allow 3128/tcp
    echo "Web Proxy allowed."
fi

# Reload UFW to apply the changes
sudo ufw reload

echo "Firewall enabled and configured with the necessary rules."
