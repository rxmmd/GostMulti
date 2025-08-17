#!/bin/bash

#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project directory
PROJECT_DIR="/opt/6to4tunnel"
CONFIG_DIR="$PROJECT_DIR/config"
TEMPLATES_DIR="$PROJECT_DIR/views"
STATIC_DIR="$PROJECT_DIR/public"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install dependencies
install_dependencies() {
    echo -e "${GREEN}Updating package list and installing dependencies...${NC}"
    if [ -f /etc/debian_version ]; then
        sudo apt update
        sudo apt install -y nodejs npm curl gzip python3 make g++ build-essential libatomic1 netplan.io || {
            echo -e "${RED}Failed to install system dependencies${NC}"
            exit 1
        }
    elif [ -f /etc/redhat-release ]; then
        sudo yum install -y epel-release
        sudo yum install -y nodejs npm curl gzip python3 make gcc-c++ libatomic netplan || {
            echo -e "${RED}Failed to install system dependencies${NC}"
            exit 1
        }
    else
        echo -e "${RED}Unsupported OS. Please install dependencies manually.${NC}"
        exit 1
    fi

    # Create project directory if it doesn't exist
    if [ ! -d "$PROJECT_DIR" ]; then
        echo -e "${GREEN}Creating project directory $PROJECT_DIR...${NC}"
        sudo mkdir -p "$PROJECT_DIR" || {
            echo -e "${RED}Failed to create project directory $PROJECT_DIR${NC}"
            exit 1
        }
        sudo chown -R www-data:www-data "$PROJECT_DIR" || {
            echo -e "${RED}Failed to set ownership for $PROJECT_DIR${NC}"
            exit 1
        }
        sudo chmod -R 755 "$PROJECT_DIR" || {
            echo -e "${RED}Failed to set permissions for $PROJECT_DIR${NC}"
            exit 1
        }
    fi

    echo -e "${GREEN}Installing Node.js packages...${NC}"
    cd "$PROJECT_DIR" || {
        echo -e "${RED}Failed to change directory to $PROJECT_DIR${NC}"
        exit 1
    }
    sudo npm install express bcrypt body-parser express-session ejs --no-save || {
        echo -e "${RED}Failed to install Node.js packages${NC}"
        exit 1
    }

    # Verify bcrypt installation
    if ! node -e "require('bcrypt')" 2>/dev/null; then
        echo -e "${RED}bcrypt is not installed correctly. Attempting to reinstall...${NC}"
        sudo npm uninstall bcrypt
        sudo npm install bcrypt --build-from-source || {
            echo -e "${RED}Failed to reinstall bcrypt${NC}"
            exit 1
        }
    fi
    echo -e "${GREEN}All dependencies installed successfully.${NC}"
}

# Function to check and install dependencies
check_and_install() {
    local missing_deps=()
    for cmd in node npm curl python3; do
        if ! command_exists "$cmd"; then
            missing_deps+=("$cmd")
        fi
    done
    
    # Check if project directory exists
    if [ ! -d "$PROJECT_DIR" ]; then
        echo -e "${RED}Project directory $PROJECT_DIR does not exist. It will be created during installation.${NC}"
        missing_deps+=("project_directory")
    fi
    
    # Check if Node.js packages are installed
    if [ -d "$PROJECT_DIR" ]; then
        cd "$PROJECT_DIR" || {
            echo -e "${RED}Failed to change directory to $PROJECT_DIR${NC}"
            exit 1
        }
        if ! npm list express bcrypt body-parser express-session ejs >/dev/null 2>&1; then
            echo -e "${RED}Some Node.js packages are missing. They will be installed.${NC}"
            missing_deps+=("node_packages")
        fi
    fi

    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${RED}Missing dependencies: ${missing_deps[*]}. Installing...${NC}"
        install_dependencies
    else
        echo -e "${GREEN}All required dependencies and project directory are already set up.${NC}"
    fi
}

# Function to install the application
# Function to generate hashed password
generate_hashed_password() {
    local password="$1"
    local hashed_password
    hashed_password=$(node -e "const bcrypt = require('bcrypt'); bcrypt.hash('$password', 10, (err, hash) => { if (err) console.log(''); else console.log(hash); });" 2>/dev/null)
    if [ -z "$hashed_password" ]; then
        echo -e "${RED}Failed to generate hashed password. Retrying with alternative method...${NC}"
        hashed_password=$(node -e "const bcrypt = require('bcrypt'); console.log(bcrypt.hashSync('$password', 10));" 2>/dev/null)
        if [ -z "$hashed_password" ]; then
            echo -e "${RED}Failed to generate hashed password after retry. Ensure bcrypt is installed correctly.${NC}"
            exit 1
        fi
    fi
    echo "$hashed_password"
}
install_application() {
    # Check and install dependencies
    check_and_install

    # Get web port from user
    read -p "Enter the web port (default 5000): " WEB_PORT
    WEB_PORT=${WEB_PORT:-5000}
    if ! [[ "$WEB_PORT" =~ ^[0-9]+$ ]] || [ "$WEB_PORT" -lt 1024 ] || [ "$WEB_PORT" -gt 65535 ]; then
        echo -e "${RED}Invalid port. Using default port 5000.${NC}"
        WEB_PORT=5000
    fi

    # Get username and password from user
    read -p "Enter username for web panel: " USERNAME
    if [ -z "$USERNAME" ]; then
        echo -e "${RED}Username cannot be empty. Exiting...${NC}"
        exit 1
    fi
    read -s -p "Enter password for web panel: " PASSWORD
    echo
    if [ -z "$PASSWORD" ]; then
        echo -e "${RED}Password cannot be empty. Exiting...${NC}"
        exit 1
    fi

    # Generate hashed password using Node.js
    HASHED_PASSWORD=$(node -e "const bcrypt = require('bcrypt'); bcrypt.hash('$PASSWORD', 10, (err, hash) => { if (err) console.log(''); else console.log(hash); });" 2>/dev/null)
    if [ -z "$HASHED_PASSWORD" ]; then
        echo -e "${RED}Failed to generate hashed password. Ensure bcrypt is installed.${NC}"
        exit 1
    fi

    # Create project directory and files
    echo -e "${GREEN}Creating project directory and files at $PROJECT_DIR...${NC}"
    sudo mkdir -p "$PROJECT_DIR" "$CONFIG_DIR" "$TEMPLATES_DIR" "$STATIC_DIR" || { echo -e "${RED}Failed to create directories${NC}"; exit 1; }
    # Create helper script for moving gost service file
    cat <<EOF | sudo tee "/usr/local/bin/move_gost_service.sh" >/dev/null || { echo -e "${RED}Failed to create move_gost_service.sh${NC}"; exit 1; }
    #!/bin/bash
    mv /tmp/gost_0.service.tmp /usr/lib/systemd/system/gost_0.service
EOF
    sudo chmod +x "/usr/local/bin/move_gost_service.sh" || { echo -e "${RED}Failed to set permissions on move_gost_service.sh${NC}"; exit 1; }
    # Save username and hashed password to config file
    echo -e "username=$USERNAME\npassword=$HASHED_PASSWORD" | sudo tee "$CONFIG_DIR/credentials.conf" >/dev/null || { echo -e "${RED}Failed to write credentials${NC}"; exit 1; }
    sudo chmod 600 "$CONFIG_DIR/credentials.conf" || { echo -e "${RED}Failed to set permissions on credentials${NC}"; exit 1; }

    # Create package.json
    cat <<EOF | sudo tee "$PROJECT_DIR/package.json" >/dev/null || { echo -e "${RED}Failed to create package.json${NC}"; exit 1; }
{
  "name": "6to4tunnel",
  "version": "1.0.0",
  "description": "6to4 Tunnel Manager",
  "main": "app.js",
  "dependencies": {
    "express": "^4.17.1",
    "bcrypt": "^5.0.1",
    "body-parser": "^1.19.0",
    "express-session": "^1.17.2",
    "ejs": "^3.1.6"
  },
  "scripts": {
    "start": "node app.js"
  }
}
EOF

    # Create Node.js app
    cat <<'EOF' | sudo tee "$PROJECT_DIR/app.js" >/dev/null || { echo -e "${RED}Failed to create app.js${NC}"; exit 1; }
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const fs = require('fs');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

const app = express();
const port = process.env.WEB_PORT || 5000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(__dirname + '/public'));
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

app.use(session({
    secret: 'supersecretkey', // Change this in production!
    resave: false,
    saveUninitialized: false
}));

// Middleware to check if user is authenticated
const isAuthenticated = (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/login');
    }
};

// Load credentials
function loadCredentials() {
    const credentials = {};
    try {
        const data = fs.readFileSync(__dirname + '/config/credentials.conf', 'utf8');
        data.split('\n').forEach(line => {
            const [key, value] = line.split('=');
            if (key && value) credentials[key] = value;
        });
    } catch (err) {
        console.error('Error loading credentials:', err);
    }
    return credentials;
}

// Validate IP addresses
function isValidIp(ip) {
    if (!ip) return false;
    const ipv4Pattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Pattern = /^[0-9a-fA-F:./]+$/;
    return ipv4Pattern.test(ip.trim()) || ipv6Pattern.test(ip.trim());
}

// Validate tunnel name
function isValidTunnelName(name) {
    if (!name) return false;
    return /^[a-zA-Z0-9_]+$/.test(name.trim());
}

app.get('/', isAuthenticated, (req, res) => {
    res.render('index', { message: req.session.message });
    req.session.message = null;
});

app.get('/login', (req, res) => {
    res.render('login', { message: req.session.login_message });
    req.session.login_message = null;
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const credentials = loadCredentials();
    try {
        if (username && password && credentials.username && await bcrypt.compare(password, credentials.password)) {
            req.session.user = username;
            res.redirect('/');
        } else {
            req.session.login_message = 'Invalid username or password';
            res.redirect('/login');
        }
    } catch (err) {
        req.session.login_message = 'Error: ' + err.message;
        res.redirect('/login');
    }
});

app.get('/logout', isAuthenticated, (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.get('/configure_iran_server_page', isAuthenticated, (req, res) => {
    res.render('configure_iran_server', { message: req.session.iran_message, alertType: req.session.iran_alertType });
    req.session.iran_message = null;
    req.session.iran_alertType = null;
});

app.post('/configure_iran_server', isAuthenticated, async (req, res) => {
    const { tunnel_name, remote_ip, local_ip, ipv6_addr, ipv6_subnet } = req.body;
    if (!tunnel_name || !remote_ip || !local_ip || !ipv6_addr || !ipv6_subnet) {
        req.session.iran_message = 'Iran server failed';
        req.session.iran_alertType = 'danger';
        return res.redirect('/configure_iran_server_page');
    }
    if (!isValidTunnelName(tunnel_name) || !isValidIp(remote_ip) || !isValidIp(local_ip) || !isValidIp(ipv6_addr) || !isValidIp(ipv6_subnet)) {
        req.session.iran_message = 'Iran server failed';
        req.session.iran_alertType = 'danger';
        return res.redirect('/configure_iran_server_page');
    }

    const prefix = ipv6_subnet.split('::/')[1] || '64';

    const commands = [
        `sudo ip tunnel add ${tunnel_name} mode sit remote ${remote_ip} local ${local_ip} ttl 255`,
        `sudo ip link set ${tunnel_name} up`,
        `sudo ip addr add ${ipv6_addr}/${prefix} dev ${tunnel_name}`,
        `sudo ip -6 route add ${ipv6_subnet} dev ${tunnel_name}`
    ];

    try {
        for (const cmd of commands) {
            const { stdout, stderr } = await execPromise(cmd);
            if (stderr) {
                throw new Error(stderr);
            }
        }
        // Fetch tunnel info
        const { stdout: tunnel_info } = await execPromise(`ip tunnel show ${tunnel_name}`);
        const remote_match = tunnel_info.match(/remote ([0-9.]+)/);
        const local_match = tunnel_info.match(/local ([0-9.]+)/);
        if (!remote_match || !local_match) {
            throw new Error('Could not fetch tunnel info.');
        }
        const fetched_remote_ip = remote_match[1];
        const fetched_local_ip = local_match[1];

        // Fetch IPv6 info
        const { stdout: ipv6_info_stdout } = await execPromise(`ip -6 addr show dev ${tunnel_name} | grep inet6 | awk '{print $2}' | head -n 1`);
        const ipv6_addr_subnet = ipv6_info_stdout.trim();
        if (!ipv6_addr_subnet) {
            throw new Error(`No IPv6 address found for tunnel '${tunnel_name}'.`);
        }

        // Create Netplan configuration file
        const netplan_content = `network:
  version: 2
  tunnels:
    ${tunnel_name}:
      mode: sit
      remote: ${fetched_remote_ip}
      local: ${fetched_local_ip}
      addresses:
        - "${ipv6_addr_subnet}"
`;
        await execPromise(`sudo tee /etc/netplan/${tunnel_name}-netcfg.yaml > /dev/null << 'EOF'\n${netplan_content}\nEOF`);
        await execPromise('sudo netplan apply');
        req.session.iran_message = 'تـانـل سـرور ایـران انـجـام شـد ✅ ';
        req.session.iran_alertType = 'success';
    } catch (err) {
        req.session.iran_message = 'Iran server failed';
        req.session.iran_alertType = 'danger';
    }
    res.redirect('/configure_iran_server_page');
});

app.get('/configure_khaerj_server_page', isAuthenticated, (req, res) => {
    res.render('configure_khaerj_server', { message: req.session.khaerj_message, alertType: req.session.khaerj_alertType });
    req.session.khaerj_message = null;
    req.session.khaerj_alertType = null;
});

app.post('/configure_khaerj_server', isAuthenticated, async (req, res) => {
    const { tunnel_name, remote_ip, local_ip, ipv6_addr, ipv6_subnet } = req.body;
    if (!tunnel_name || !remote_ip || !local_ip || !ipv6_addr || !ipv6_subnet) {
        req.session.khaerj_message = 'Khaerj server failed';
        req.session.khaerj_alertType = 'danger';
        return res.redirect('/configure_khaerj_server_page');
    }
    if (!isValidTunnelName(tunnel_name) || !isValidIp(remote_ip) || !isValidIp(local_ip) || !isValidIp(ipv6_addr) || !isValidIp(ipv6_subnet)) {
        req.session.khaerj_message = 'Khaerj server failed';
        req.session.khaerj_alertType = 'danger';
        return res.redirect('/configure_khaerj_server_page');
    }

    const prefix = ipv6_subnet.split('::/')[1] || '64';

    const commands = [
        `sudo ip tunnel add ${tunnel_name} mode sit remote ${remote_ip} local ${local_ip} ttl 255`,
        `sudo ip link set ${tunnel_name} up`,
        `sudo ip addr add ${ipv6_addr}/${prefix} dev ${tunnel_name}`,
        `sudo ip -6 route add ${ipv6_subnet} dev ${tunnel_name}`
    ];

    try {
        for (const cmd of commands) {
            const { stdout, stderr } = await execPromise(cmd);
            if (stderr) {
                throw new Error(stderr);
            }
        }
        // Fetch tunnel info
        const { stdout: tunnel_info } = await execPromise(`ip tunnel show ${tunnel_name}`);
        const remote_match = tunnel_info.match(/remote ([0-9.]+)/);
        const local_match = tunnel_info.match(/local ([0-9.]+)/);
        if (!remote_match || !local_match) {
            throw new Error('Could not fetch tunnel info.');
        }
        const fetched_remote_ip = remote_match[1];
        const fetched_local_ip = local_match[1];

        // Fetch IPv6 info
        const { stdout: ipv6_info_stdout } = await execPromise(`ip -6 addr show dev ${tunnel_name} | grep inet6 | awk '{print $2}' | head -n 1`);
        const ipv6_addr_subnet = ipv6_info_stdout.trim();
        if (!ipv6_addr_subnet) {
            throw new Error(`No IPv6 address found for tunnel '${tunnel_name}'.`);
        }

        // Create Netplan configuration file
        const netplan_content = `network:
  version: 2
  tunnels:
    ${tunnel_name}:
      mode: sit
      remote: ${fetched_remote_ip}
      local: ${fetched_local_ip}
      addresses:
        - "${ipv6_addr_subnet}"
`;
        await execPromise(`sudo tee /etc/netplan/${tunnel_name}-netcfg.yaml > /dev/null << 'EOF'\n${netplan_content}\nEOF`);
        await execPromise('sudo netplan apply');
        req.session.khaerj_message = 'تـانـل سـرور خـارج انـجـام شـد ✅ ';
        req.session.khaerj_alertType = 'success';
    } catch (err) {
        req.session.khaerj_message = 'Khaerj server failed';
        req.session.khaerj_alertType = 'danger';
    }
    res.redirect('/configure_khaerj_server_page');
});

app.get('/configure_gost_page', isAuthenticated, (req, res) => {
    req.session.showGost = true;
    res.redirect('/gost');
});

app.get('/gost', isAuthenticated, (req, res) => {
    if (!req.session.showGost) return res.redirect('/');
    res.render('gost', { message: req.session.gost_message, alertType: req.session.gost_alertType });
    req.session.gost_message = null;
    req.session.gost_alertType = null;
});

app.get('/install_gost_page', isAuthenticated, (req, res) => {
    res.render('install_gost', { message: req.session.install_gost_message, alertType: req.session.install_gost_alertType });
    req.session.install_gost_message = null;
    req.session.install_gost_alertType = null;
});

app.post('/install_gost', isAuthenticated, async (req, res) => {
    try {
        const panel_ips = req.body.panel_ips ? req.body.panel_ips.split(',').map(ip => ip.trim()) : [];
        const panel_ports = req.body.panel_ports ? req.body.panel_ports.split(',').map(port => port.trim()) : [];
        const inbound_ips = req.body.inbound_ips ? req.body.inbound_ips.split(',').map(ip => ip.trim()) : [];
        const inbound_ports = req.body.inbound_ports ? req.body.inbound_ports.split(',').map(port => port.trim()) : [];
        const protocol_option = req.body.protocol_option || '1';
        const panel_random_ports = panel_ips.map((_, i) => req.body[`panel_random_port_${i}`] || Math.floor(1000 + Math.random() * 55535));

        if (panel_ips.length !== panel_ports.length || panel_ips.length !== panel_random_ports.length) {
            throw new Error('Number of panel IPs, ports, and random ports must match.');
        }

        let protocols = [];
        if (protocol_option === '1') protocols = ['tcp'];
        else if (protocol_option === '2') protocols = ['udp'];
        else if (protocol_option === '3') protocols = ['tcp', 'udp'];
        else {
            throw new Error('Invalid protocol option.');
        }

        let exec_start_lines = [];
        for (const proto of protocols) {
            for (let i = 0; i < panel_ips.length; i++) {
                const panel_ip = panel_ips[i];
                const panel_port = panel_ports[i];
                const panel_random_port = panel_random_ports[i];
                if (!/^\d+$/.test(panel_random_port) || parseInt(panel_random_port) > 65535) {
                    throw new Error('Invalid random port value.');
                }
                exec_start_lines.push(`${proto}://:${panel_random_port}/[${panel_ip}]:${panel_port}`);
            }
            for (let i = 0; i < inbound_ips.length; i++) {
                const inbound_ip = inbound_ips[i];
                const inbound_port = inbound_ports[i];
                exec_start_lines.push(`${proto}://:${inbound_port}/[${inbound_ip}]:${inbound_port}`);
            }
        }

        // Build service content
        const service_content = [
            "[Unit]",
            "Description=GO Simple Tunnel for Multiple External IPs",
            "After=network.target",
            "Wants=network.target",
            "",
            "[Service]",
            "Type=simple",
            'Environment="GOST_LOGGER_LEVEL=fatal"',
            "ExecStart=/usr/local/bin/gost \\"
        ];
        exec_start_lines.forEach((line, index) => {
            service_content.push(`    -L=${line}${index < exec_start_lines.length - 1 ? ' \\' : ''}`);
        });
        service_content.push("", "[Install]", "WantedBy=multi-user.target");

        // Detect architecture and download the correct gost binary
        const { stdout: arch } = await execPromise('uname -m');
        let binaryName;
        if (arch.trim() === 'x86_64') {
            binaryName = 'gost-linux-amd64-2.11.5.gz';
        } else if (arch.trim() === 'aarch64') {
            binaryName = 'gost-linux-arm64-2.11.5.gz';
        } else {
            throw new Error('Unsupported architecture: ' + arch.trim());
        }

        await execPromise(`curl -L -o /tmp/${binaryName} https://github.com/ginuerzh/gost/releases/download/v2.11.5/${binaryName}`);
        if (!fs.existsSync(`/tmp/${binaryName}`)) {
            throw new Error('Failed to download gost binary');
        }

        await execPromise(`gunzip /tmp/${binaryName}`);
        const binaryFile = binaryName.replace('.gz', '');
        if (!fs.existsSync(`/tmp/${binaryFile}`)) {
            throw new Error('Failed to extract gost binary');
        }

        await execPromise(`sudo mv /tmp/${binaryFile} /usr/local/bin/gost`);
        await execPromise('sudo chmod +x /usr/local/bin/gost');

        fs.writeFileSync('/tmp/gost_0.service.tmp', service_content.join('\n'));

        await execPromise('sudo /usr/local/bin/move_gost_service.sh');

        await execPromise('sudo chown www-data:www-data /usr/lib/systemd/system/gost_0.service');
        await execPromise('sudo chmod 644 /usr/lib/systemd/system/gost_0.service');
        await execPromise('sudo systemctl daemon-reload');
        await execPromise('sudo systemctl enable gost_0.service');
        await execPromise('sudo systemctl start gost_0.service');

        req.session.install_gost_message = 'تـانـل گـاسـت بـا مـوفـقـیـت نـصـب شـد ✅';
        req.session.install_gost_alertType = 'success';
    } catch (err) {
        req.session.install_gost_message = 'Install gost failed';
        req.session.install_gost_alertType = 'danger';
    }
    res.redirect('/install_gost_page');
});

app.get('/add_new_ipv6_page', isAuthenticated, (req, res) => {
    res.render('add_new_ipv6', { message: req.session.add_ipv6_message, alertType: req.session.add_ipv6_alertType });
    req.session.add_ipv6_message = null;
    req.session.add_ipv6_alertType = null;
});

app.post('/add_new_ipv6_panel', isAuthenticated, async (req, res) => {
    const { panel_ip, panel_port, panel_random_port, protocol } = req.body;
    if (!panel_ip || !panel_port || !panel_random_port || !protocol) {
        req.session.add_ipv6_message = 'New Panel IPv6 failed';
        req.session.add_ipv6_alertType = 'danger';
        return res.redirect('/add_new_ipv6_page');
    }
    if (!isValidIp(panel_ip) || !/^\d+$/.test(panel_port) || !/^\d+$/.test(panel_random_port)) {
        req.session.add_ipv6_message = 'New Panel IPv6 failed';
        req.session.add_ipv6_alertType = 'danger';
        return res.redirect('/add_new_ipv6_page');
    }

    let new_lines = [];
    try {
        new_lines.push(`${protocol}://:${panel_random_port}/[${panel_ip}]:${panel_port}`);
        const new_lines_str = new_lines.join('|');
        const { stdout, stderr } = await execPromise(`python3 /tmp/gost_update.py "${new_lines_str}"`);
        if (stderr) {
            req.session.add_ipv6_message = 'New Panel IPv6 failed';
            req.session.add_ipv6_alertType = 'danger';
        } else {
            req.session.add_ipv6_message = 'بـا مـوفـقـیـت ipv6 پـنـل اضـافـه شد ✅';
            req.session.add_ipv6_alertType = 'success';
        }
    } catch (err) {
        req.session.add_ipv6_message = 'New Panel IPv6 failed';
        req.session.add_ipv6_alertType = 'danger';
    }
    res.redirect('/add_new_ipv6_page');
});

app.post('/add_new_ipv6_inbound', isAuthenticated, async (req, res) => {
    const { inbound_ip, inbound_port, protocol } = req.body;
    if (!inbound_ip || !inbound_port || !protocol) {
        req.session.add_ipv6_message = 'New Inbound IPv6 failed';
        req.session.add_ipv6_alertType = 'danger';
        return res.redirect('/add_new_ipv6_page');
    }
    if (!isValidIp(inbound_ip) || !/^\d+$/.test(inbound_port)) {
        req.session.add_ipv6_message = 'New Inbound IPv6 failed';
        req.session.add_ipv6_alertType = 'danger';
        return res.redirect('/add_new_ipv6_page');
    }

    let new_lines = [];
    try {
        new_lines.push(`${protocol}://:${inbound_port}/[${inbound_ip}]:${inbound_port}`);
        const new_lines_str = new_lines.join('|');
        const { stdout, stderr } = await execPromise(`python3 /tmp/gost_update.py "${new_lines_str}"`);
        if (stderr) {
            req.session.add_ipv6_message = 'New Inbound IPv6 failed';
            req.session.add_ipv6_alertType = 'danger';
        } else {
            req.session.add_ipv6_message = 'بـا مـوفـقـیـت ipv6 اینباند اضـافـه شد ✅';
            req.session.add_ipv6_alertType = 'success';
        }
    } catch (err) {
        req.session.add_ipv6_message = 'New Inbound IPv6 failed';
        req.session.add_ipv6_alertType = 'danger';
    }
    res.redirect('/add_new_ipv6_page');
});

app.get('/restart_tunnel_page', isAuthenticated, (req, res) => {
    res.render('restart_tunnel', { message: req.session.restart_message, alertType: req.session.restart_alertType });
    req.session.restart_message = null;
    req.session.restart_alertType = null;
});

app.post('/restart_tunnel', isAuthenticated, async (req, res) => {
    try {
        const { stdout: reloadStdout, stderr: reloadStderr } = await execPromise('sudo systemctl daemon-reload');
        if (reloadStderr) {
            throw new Error(reloadStderr);
        }
        const { stdout: restartStdout, stderr: restartStderr } = await execPromise('sudo systemctl restart gost_0.service');
        if (restartStderr) {
            throw new Error(restartStderr);
        }
        req.session.restart_message = 'تـانل گـاسـت بـا مـوفـقـیـت راه انـدازی شـد ✅';
        req.session.restart_alertType = 'success';
    } catch (err) {
        req.session.restart_message = 'Restart tunnel failed';
        req.session.restart_alertType = 'danger';
    }
    res.redirect('/restart_tunnel_page');
});

app.get('/uninstall_gost_page', isAuthenticated, (req, res) => {
    res.render('uninstall_gost', { message: req.session.uninstall_gost_message, alertType: req.session.uninstall_gost_alertType });
    req.session.uninstall_gost_message = null;
    req.session.uninstall_gost_alertType = null;
});

app.post('/uninstall_gost', isAuthenticated, async (req, res) => {
    try {
        await execPromise('sudo systemctl stop gost_0.service || true');
        await execPromise('sudo systemctl disable gost_0.service || true');
        await execPromise('sudo rm -f /usr/lib/systemd/system/gost_0.service');
        await execPromise('sudo rm -f /etc/systemd/system/multi-user.target.wants/gost_0.service');
        await execPromise('sudo systemctl daemon-reload');
        await execPromise('sudo killall -9 gost || true');
        await execPromise('sudo rm -f /usr/local/bin/gost');
        await execPromise('sudo rm -rf /etc/gost');
        await execPromise('sudo rm -f /usr/bin/auto_restart_cronjob.sh');
        await execPromise('crontab -l | grep -v "/usr/bin/auto_restart_cronjob.sh" | crontab -');
        await execPromise('sudo systemctl stop sysctl-custom || true');
        await execPromise('sudo systemctl disable sysctl-custom || true');
        await execPromise('sudo rm -f /etc/systemd/system/sysctl-custom.service');
        await execPromise('sudo rm -f /etc/systemd/system/multi-user.target.wants/sysctl-custom.service');
        await execPromise('sudo systemctl daemon-reload');
        req.session.uninstall_gost_message = 'تـانل گـاسـت بـا مـوفـقـیـت حـذف شـد ✅';
        req.session.uninstall_gost_alertType = 'success';
    } catch (err) {
        req.session.uninstall_gost_message = 'Uninstall gost failed';
        req.session.uninstall_gost_alertType = 'danger';
    }
    res.redirect('/uninstall_gost_page');
});

app.get('/test_ping_page', isAuthenticated, (req, res) => {
    res.render('test_ping_page', { message: req.session.ping_message, alertType: req.session.ping_alertType });
    req.session.ping_message = null;
    req.session.ping_alertType = null;
});

app.post('/test_ping', isAuthenticated, async (req, res) => {
    const { ping_address } = req.body;
    if (!ping_address) {
        req.session.ping_message = 'Test ping failed';
        req.session.ping_alertType = 'danger';
        return res.redirect('/test_ping_page');
    }
    if (!isValidIp(ping_address)) {
        req.session.ping_message = 'Test ping failed';
        req.session.ping_alertType = 'danger';
        return res.redirect('/test_ping_page');
    }

    try {
        const { stdout } = await execPromise(`ping6 -c 4 ${ping_address}`);
        if (stdout.includes('0% packet loss')) {
            req.session.ping_message = 'تـسـت پـیـنـگ مـوفـقـیـت آمـیـز بود ✅';
            req.session.ping_alertType = 'success';
        } else {
            req.session.ping_message = 'Test ping failed';
            req.session.ping_alertType = 'danger';
        }
    } catch (err) {
        req.session.ping_message = 'Test ping failed';
        req.session.ping_alertType = 'danger';
    }
    res.redirect('/test_ping_page');
});

app.get('/delete_tunnel_page', isAuthenticated, async (req, res) => {
    let tunnels = [];
    try {
        const { stdout } = await execPromise('ip tunnel show');
        tunnels = stdout.split('\n').filter(line => line.trim()).map(line => line.split(':')[0].trim());
    } catch (err) {
        console.error('Error fetching tunnels:', err);
    }
    res.render('delete_tunnel_page', { message: req.session.delete_tunnel_message, alertType: req.session.delete_tunnel_alertType, tunnels });
    req.session.delete_tunnel_message = null;
    req.session.delete_tunnel_alertType = null;
});

app.post('/delete_tunnel', isAuthenticated, async (req, res) => {
    const { tunnel_name } = req.body;
    if (!tunnel_name) {
        req.session.delete_tunnel_message = 'Delete tunnel failed';
        req.session.delete_tunnel_alertType = 'danger';
        return res.redirect('/delete_tunnel_page');
    }
    if (!isValidTunnelName(tunnel_name)) {
        req.session.delete_tunnel_message = 'Delete tunnel failed';
        req.session.delete_tunnel_alertType = 'danger';
        return res.redirect('/delete_tunnel_page');
    }

    try {
        const { stderr: showErr } = await execPromise(`ip tunnel show ${tunnel_name}`);
        if (showErr) {
            req.session.delete_tunnel_message = 'Delete tunnel failed';
            req.session.delete_tunnel_alertType = 'danger';
            return res.redirect('/delete_tunnel_page');
        }

        await execPromise(`sudo ip link set ${tunnel_name} down`);
        const { stderr: delErr } = await execPromise(`sudo ip tunnel del ${tunnel_name}`);
        if (delErr) {
            req.session.delete_tunnel_message = 'Delete tunnel failed';
            req.session.delete_tunnel_alertType = 'danger';
            return res.redirect('/delete_tunnel_page');
        }

        const netplan_file = `/etc/netplan/${tunnel_name}-netcfg.yaml`;
        if (fs.existsSync(netplan_file)) {
            await execPromise(`sudo rm ${netplan_file}`);
            await execPromise('sudo netplan apply');
        }
        req.session.delete_tunnel_message = 'تـانـل بـا مـوفـقـیـت حـذف شـد ✅';
        req.session.delete_tunnel_alertType = 'success';
    } catch (err) {
        req.session.delete_tunnel_message = 'Delete tunnel failed';
        req.session.delete_tunnel_alertType = 'danger';
    }
    res.redirect('/delete_tunnel_page');
});

app.get('/delete_netplan_page', isAuthenticated, async (req, res) => {
    let netplans = [];
    try {
        const { stdout } = await execPromise('ls /etc/netplan/');
        netplans = stdout.split('\n').filter(file => file.trim().endsWith('-netcfg.yaml')).map(file => file.trim());
    } catch (err) {
        console.error('Error fetching netplans:', err);
    }
    res.render('delete_netplan', { message: req.session.delete_netplan_message, alertType: req.session.delete_netplan_alertType, netplans });
    req.session.delete_netplan_message = null;
    req.session.delete_netplan_alertType = null;
});

app.post('/delete_netplan', isAuthenticated, async (req, res) => {
    const { netplan_file } = req.body;
    if (!netplan_file) {
        req.session.delete_netplan_message = 'Delete netplan failed';
        req.session.delete_netplan_alertType = 'danger';
        return res.redirect('/delete_netplan_page');
    }
    if (!/^[a-zA-Z0-9_-]+-netcfg\.yaml$/.test(netplan_file)) {
        req.session.delete_netplan_message = 'Delete netplan failed';
        req.session.delete_netplan_alertType = 'danger';
        return res.redirect('/delete_netplan_page');
    }

    const netplan_path = `/etc/netplan/${netplan_file}`;
    try {
        if (fs.existsSync(netplan_path)) {
            await execPromise(`sudo rm ${netplan_path}`);
            await execPromise('sudo netplan apply');
            req.session.delete_netplan_message = 'فـایـل نـت پـلـن حـذف شـد ✅';
            req.session.delete_netplan_alertType = 'success';
        } else {
            req.session.delete_netplan_message = 'Delete netplan failed';
            req.session.delete_netplan_alertType = 'danger';
        }
    } catch (err) {
        req.session.delete_netplan_message = 'Delete netplan failed';
        req.session.delete_netplan_alertType = 'danger';
    }
    res.redirect('/delete_netplan_page');
});


app.get('/uninstall_page', isAuthenticated, (req, res) => {
    res.render('uninstall', { message: req.session.message });
    req.session.message = null;
});

app.post('/uninstall', isAuthenticated, async (req, res) => {
    let output = '';
    try {
        await execPromise('sudo systemctl stop 6to4tunnel');
        await execPromise('sudo systemctl disable 6to4tunnel');
        await execPromise('sudo rm /etc/systemd/system/6to4tunnel.service');
        await execPromise('sudo systemctl daemon-reload');
        await execPromise('sudo rm /etc/sudoers.d/6to4tunnel');
        fs.rmSync(__dirname, { recursive: true, force: true });
        output += 'Uninstalling...\nApplication uninstalled successfully\n';
        req.session.message = 'Application uninstalled successfully. Please restart the server to complete cleanup.\n${output}';
    } catch (err) {
        req.session.message = `Error during uninstall: ${err.message}\n${output}`;
    }
    res.redirect('/uninstall_page');
});
app.get('/gost_status_page', isAuthenticated, (req, res) => {
    res.render('gost_status', { message: req.session.gost_status_message, alertType: req.session.gost_status_alertType, status: null });
    req.session.gost_status_message = null;
    req.session.gost_status_alertType = null;
});

app.post('/gost_status', isAuthenticated, async (req, res) => {
    let output = '';
    let status = 'Unknown';
    try {
        const { stdout, stderr } = await execPromise('sudo -n systemctl status gost_0.service --no-pager');
        output += `${stdout || stderr}\n`;
        if (stderr && stderr.includes('password')) {
            status = 'Error';
            req.session.gost_status_message = 'Gost status failed';
            req.session.gost_status_alertType = 'danger';
        } else if (stderr && stderr.includes('Unit gost_0.service could not be found') || stdout.includes('not-found')) {
            status = 'Not Installed';
            req.session.gost_status_message = 'Gost status failed';
            req.session.gost_status_alertType = 'danger';
        } else if (stderr) {
            status = 'Error';
            req.session.gost_status_message = 'Gost status failed';
            req.session.gost_status_alertType = 'danger';
        } else if (stdout.includes('active (running)')) {
            status = 'Running';
            req.session.gost_status_message = 'وضـعـیـت تـانـل گـاسـت :  ✅ ';
            req.session.gost_status_alertType = 'success';
        } else if (stdout.includes('inactive (dead)')) {
            status = 'Stopped';
            req.session.gost_status_message = 'وضـعـیـت تـانـل گـاسـت :  ✅ ';
            req.session.gost_status_alertType = 'success';
        } else if (stdout.includes('failed')) {
            status = 'Failed';
            req.session.gost_status_message = 'Gost status failed';
            req.session.gost_status_alertType = 'danger';
        } else {
            status = 'Unknown';
            req.session.gost_status_message = 'Gost status failed';
            req.session.gost_status_alertType = 'danger';
        }
    } catch (err) {
        req.session.gost_status_message = 'Gost status failed';
        req.session.gost_status_alertType = 'danger';
        status = 'Error';
    }
    res.render('gost_status', { message: req.session.gost_status_message, alertType: req.session.gost_status_alertType, status: status });
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
EOF

    # Install Node.js dependencies
    cd "$PROJECT_DIR" || { echo -e "${RED}Failed to change directory to $PROJECT_DIR${NC}"; exit 1; }
    sudo npm install express bcrypt body-parser express-session ejs || { echo -e "${RED}Failed to install Node.js packages${NC}"; exit 1; }

    # Create login EJS template
# Replace the entire cat <<EOF block for "$TEMPLATES_DIR/login.ejs" with this:
# Replace the entire cat <<EOF block for "$TEMPLATES_DIR/login.ejs" with this:
# Replace the entire cat <<EOF block for "$TEMPLATES_DIR/login.ejs" with this:

cat <<EOF | sudo tee "$TEMPLATES_DIR/login.ejs" >/dev/null || { echo -e "${RED}Failed to create login.ejs${NC}"; exit 1; }
<!DOCTYPE html>
<html lang="fa">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ورود به سیستم</title>
<style>
:root {
  --primary-color: #9c27b0;
  --primary-light: #bb86fc;
  --primary-dark: #6a0dad;
  --background-dark: #121212;
  --surface-dark: #1e1e1e;
  --text-primary: #ffffff;
  --text-secondary: rgba(255, 255, 255, 0.7);
  --error-color: #cf6679;
  --success-color: #03dac6;
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
  font-family: "Vazirmatn", "Tahoma", sans-serif;
}

body {
  background-color: var(--background-dark);
  color: var(--text-primary);
  direction: rtl;
  line-height: 1.6;
  min-height: 100vh;
  display: flex;
  justify-content: center;
  align-items: center;
  background-image: radial-gradient(circle at 10% 20%, rgba(156, 39, 176, 0.3) 0%, transparent 30%), radial-gradient(circle at 90% 80%, rgba(106, 13, 173, 0.3) 0%, transparent 30%);
  background-attachment: fixed;
}

.container {
  width: 90%;
  max-width: 400px;
  margin: 2rem auto;
  padding: 2rem;
  border-radius: 16px;
  background: rgba(30, 30, 30, 0.7);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
  border: 1px solid rgba(255, 255, 255, 0.1);
}

h1 {
  color: var(--primary-light);
  text-align: center;
  margin-bottom: 2rem;
  font-size: 1.8rem;
}

.form-group {
  margin-bottom: 1.5rem;
}

label {
  display: block;
  margin-bottom: 0.5rem;
  color: var(--text-secondary);
}

input[type="text"],
input[type="password"] {
  width: 100%;
  padding: 0.8rem 1rem;
  border-radius: 8px;
  border: 1px solid rgba(255, 255, 255, 0.1);
  background: rgba(255, 255, 255, 0.05);
  color: var(--text-primary);
  font-size: 1rem;
  transition: all 0.3s ease;
}

input[type="text"]:focus,
input[type="password"]:focus {
  outline: none;
  border-color: var(--primary-light);
  box-shadow: 0 0 0 2px rgba(187, 134, 252, 0.3);
}

input[type="text"]::placeholder,
input[type="password"]::placeholder {
  color: rgba(255, 255, 255, 0.3);
}

button {
  background: var(--primary-color);
  color: white;
  border: none;
  padding: 0.8rem 2rem;
  border-radius: 8px;
  cursor: pointer;
  font-size: 1rem;
  font-weight: bold;
  transition: all 0.3s ease;
  display: block;
  width: 100%;
  margin-top: 1rem;
}

button:hover {
  background: var(--primary-dark);
  transform: translateY(-2px);
  box-shadow: 0 5px 15px rgba(156, 39, 176, 0.4);
}

.alert {
  padding: 1rem;
  border-radius: 8px;
  margin-bottom: 1.5rem;
  line-height: 1.5;
}

.alert-danger {
  background: rgba(207, 102, 121, 0.2);
  border-left: 4px solid var(--error-color);
  color: var(--error-color);
}

.alert-success {
  background: rgba(3, 218, 198, 0.2);
  border-left: 4px solid var(--success-color);
  color: var(--success-color);
}

@media (max-width: 768px) {
  .container {
    width: 95%;
    padding: 1.5rem;
  }

  h1 {
    font-size: 1.5rem;
  }

  input[type="text"],
  input[type="password"],
  button {
    padding: 0.7rem;
  }
}

@media (max-width: 480px) {
  .container {
    width: 100%;
    padding: 1rem;
    margin: 1rem;
    border-radius: 12px;
  }

  h1 {
    font-size: 1.3rem;
  }

  .form-group {
    margin-bottom: 1rem;
  }
}

@font-face {
  font-family: "Vazirmatn";
  src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Regular.woff2") format("woff2");
  font-weight: normal;
  font-style: normal;
  font-display: swap;
}

@font-face {
  font-family: "Vazirmatn";
  src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Bold.woff2") format("woff2");
  font-weight: bold;
  font-style: normal;
  font-display: swap;
}
</style>
</head>
<body>
<div class="container">
  <h1>ورود به سیستم</h1>
  <% if (message) { %>
      <div class="alert alert-<%= alertType %>">
          <%= message %>
      </div>
  <% } %>
  <form method="POST" action="/login">
      <div class="form-group">
          <label>نام کاربری:</label>
          <input type="text" name="username" required>
      </div>
      <div class="form-group">
          <label>رمز عبور:</label>
          <input type="password" name="password" required>
      </div>
      <button type="submit">ورود 🔐</button>
  </form>
</div>
</body>
</html>
EOF

    # Create index EJS template
# Replace the entire cat <<EOF block for "$TEMPLATES_DIR/index.ejs" with this:
cat <<EOF | sudo tee "$TEMPLATES_DIR/index.ejs" >/dev/null || { echo -e "${RED}Failed to create index.ejs${NC}"; exit 1; }
<!DOCTYPE html>
<html lang="fa">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>مدیریت سرور</title>
<style>
:root {
  --primary-color: #9c27b0;
  --primary-light: #bb86fc;
  --primary-dark: #6a0dad;
  --background-dark: #121212;
  --surface-dark: #1e1e1e;
  --text-primary: #ffffff;
  --text-secondary: rgba(255, 255, 255, 0.7);
  --error-color: #cf6679;
  --success-color: #03dac6;
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
  font-family: "Vazirmatn", "Tahoma", sans-serif;
}

body {
  background-color: var(--background-dark);
  color: var(--text-primary);
  direction: rtl;
  line-height: 1.6;
  min-height: 100vh;
  display: flex;
  justify-content: center;
  align-items: center;
  background-image: radial-gradient(circle at 10% 20%, rgba(156, 39, 176, 0.3) 0%, transparent 30%), radial-gradient(circle at 90% 80%, rgba(106, 13, 173, 0.3) 0%, transparent 30%);
  background-attachment: fixed;
}

.container {
  width: 90%;
  max-width: 600px;
  margin: 2rem auto;
  padding: 2rem;
  border-radius: 16px;
  background: rgba(30, 30, 30, 0.7);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
  border: 1px solid rgba(255, 255, 255, 0.1);
}

h1 {
  color: var(--primary-light);
  text-align: center;
  margin-bottom: 2rem;
  font-size: 1.8rem;
}

.nav-button {
  display: block;
  width: 100%;
  padding: 0.8rem 1rem;
  margin-bottom: 1rem;
  background: var(--primary-color);
  color: var(--text-primary);
  text-align: center;
  text-decoration: none;
  border-radius: 8px;
  font-size: 1rem;
  font-weight: bold;
  transition: all 0.3s ease;
}

.nav-button:hover {
  background: var(--primary-dark);
  transform: translateY(-2px);
  box-shadow: 0 5px 15px rgba(156, 39, 176, 0.4);
}

.alert {
  padding: 1rem;
  border-radius: 8px;
  margin-bottom: 1.5rem;
  line-height: 1.5;
}

.alert-danger {
  background: rgba(207, 102, 121, 0.2);
  border-left: 4px solid var(--error-color);
  color: var(--error-color);
}

.alert-success {
  background: rgba(3, 218, 198, 0.2);
  border-left: 4px solid var(--success-color);
  color: var(--success-color);
}

@media (max-width: 768px) {
  .container {
    width: 95%;
    padding: 1.5rem;
  }

  h1 {
    font-size: 1.5rem;
  }

  .nav-button {
    padding: 0.7rem;
  }
}

@media (max-width: 480px) {
  .container {
    width: 100%;
    padding: 1rem;
    margin: 1rem;
    border-radius: 12px;
  }

  h1 {
    font-size: 1.3rem;
  }
}

@font-face {
  font-family: "Vazirmatn";
  src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Regular.woff2") format("woff2");
  font-weight: normal;
  font-style: normal;
  font-display: swap;
}

@font-face {
  font-family: "Vazirmatn";
  src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Bold.woff2") format("woff2");
  font-weight: bold;
  font-style: normal;
  font-display: swap;
}
</style>
</head>
<body>
<div class="container">
  <h1>مدیریت سرور</h1>
  <% if (message) { %>
      <div class="alert alert-<%= alertType %>">
          <%= message %>
      </div>
  <% } %>
  <a href="/configure_iran_server" class="nav-button">پیکربندی سرور ایران ⚙️</a>
  <a href="/configure_khaerj_server" class="nav-button">پیکربندی سرور خارج ⚙️</a>
  <a href="/test_ping" class="nav-button">تست پینگ 📡</a>
  <a href="/delete_tunnel_page" class="nav-button">حذف تونل 🗑</a>
  <a href="/delete_netplan" class="nav-button">حذف پیکربندی Netplan 🗑</a>
  <a href="/logout" class="nav-button">خروج 🔓</a>
</div>
</body>
</html>
EOF
    # Create configure_iran_server EJS template

# Replace the entire cat <<EOF block for "$TEMPLATES_DIR/configure_iran_server.ejs" with this:
cat <<EOF | sudo tee "$TEMPLATES_DIR/configure_iran_server.ejs" >/dev/null || { echo -e "${RED}Failed to create configure_iran_server.ejs${NC}"; exit 1; }
<!DOCTYPE html>
<html lang="fa">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Configure Iran Server</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  @font-face {
    font-family: "Vazirmatn";
    src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Regular.woff2") format("woff2");
    font-weight: normal;
    font-style: normal;
    font-display: swap;
  }
  @font-face {
    font-family: "Vazirmatn";
    src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Bold.woff2") format("woff2");
    font-weight: bold;
    font-style: normal;
    font-display: swap;
  }

  body {
    font-family: "Vazirmatn", sans-serif;
    direction: rtl;
    background: #2a1a3d;
    background-attachment: fixed;
    color: #e0e0e0;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    padding: 40px 20px;
    box-sizing: border-box;
    position: relative;
  }

  body::before {
    content: '';
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: radial-gradient(circle at 20% 80%, rgba(120, 119, 198, 0.3) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(255, 119, 198, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 40% 40%, rgba(120, 219, 255, 0.1) 0%, transparent 50%);
    pointer-events: none;
    z-index: -1;
  }

  .main-container {
    background: rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(25px) saturate(180%);
    -webkit-backdrop-filter: blur(25px) saturate(180%);
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: 20px;
    padding: 50px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1);
    max-width: 600px;
    width: 100%;
    text-align: center;
    position: relative;
  }

  .form-group {
    margin-bottom: 30px;
  }

  label {
    margin-bottom: 10px;
    display: block;
  }

  input.form-control {
    padding: 15px;
    border-radius: 10px;
    background: rgba(255, 255, 255, 0.1);
    border: 1px solid rgba(255, 255, 255, 0.2);
    color: #ffffff;
    width: 100%;
  }

  button.btn-primary {
    padding: 15px 30px;
    background: rgba(138, 43, 226, 0.3);
    border-radius: 15px;
    transition: all 0.3s;
    margin-top: 20px;
  }

  button.btn-primary:hover {
    background: rgba(138, 43, 226, 0.5);
  }

  .back-button {
    padding: 14px 28px;
    font-size: 1rem;
    border-radius: 25px;
    border: 1px solid rgba(255, 255, 255, 0.2);
    background: rgba(138, 43, 226, 0.15);
    backdrop-filter: blur(15px) saturate(150%);
    -webkit-backdrop-filter: blur(15px) saturate(150%);
    color: #ffffff;
    cursor: pointer;
    transition: all 0.3s ease;
    outline: none;
    margin-bottom: 20px;
    display: inline-block;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.1);
  }

  .back-button:hover {
    background: rgba(138, 43, 226, 0.25);
    border-color: rgba(255, 255, 255, 0.3);
    transform: translateY(-3px);
    box-shadow: 0 6px 20px rgba(138, 43, 226, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.15);
  }

  .alert {
    margin-bottom: 30px;
    padding: 15px;
    border-radius: 10px;
  }

  h1 {
    font-weight: bolder;
    margin-top: -20px;
    margin-bottom: 40px;
  }

  @media (max-width: 768px) {
    .main-container {
      padding: 30px;
    }
    .form-group {
      margin-bottom: 20px;
    }
  }
</style>
</head>
<body>
<div class="main-container">
  <h1></h1>
  <a href="/" class="back-button">بازگشت به صحفه اصلی 🔙</a>
  <% if (message) { %>
      <div class="alert alert-<%= alertType %>">
          <%= message %>
      </div>
  <% } %>
  <form method="POST" action="/configure_iran_server">
      <div class="form-group">
          <label>نام تانل نمونه : 6to4tunnel55</label>
          <input type="text" name="tunnel_name" class="form-control" required>
      </div>
      <div class="form-group">
          <label>آیپی سرور خارج : </label>
          <input type="text" name="remote_ip" class="form-control" required>
      </div>
      <div class="form-group">
          <label>آیپی سرور ایران : </label>
          <input type="text" name="local_ip" class="form-control" required>
      </div>
      <div class="form-group">
          <label>آدرس ipv6 نمونه : fde6:84c6:1887::1 </label>
          <input type="text" name="ipv6_addr" class="form-control" required>
      </div>
      <div class="form-group">
          <label>ساب‌نت IPv6 نمونه : fde6:84c6:1887::/64 </label>
          <input type="text" name="ipv6_subnet" class="form-control" required>
      </div>
      <button type="submit" class="btn btn-primary">ارسـال 📤</button>
  </form>
</div>
</body>
</html>
EOF

    # Create configure_khaerj_server EJS template

# Replace the entire cat <<EOF block for "$TEMPLATES_DIR/configure_khaerj_server.ejs" with this:
cat <<EOF | sudo tee "$TEMPLATES_DIR/configure_khaerj_server.ejs" >/dev/null || { echo -e "${RED}Failed to create configure_khaerj_server.ejs${NC}"; exit 1; }
<!DOCTYPE html>
<html lang="fa">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Configure Khaerj Server</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  @font-face {
    font-family: "Vazirmatn";
    src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Regular.woff2") format("woff2");
    font-weight: normal;
    font-style: normal;
    font-display: swap;
  }
  @font-face {
    font-family: "Vazirmatn";
    src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Bold.woff2") format("woff2");
    font-weight: bold;
    font-style: normal;
    font-display: swap;
  }

  body {
    font-family: "Vazirmatn", sans-serif;
    direction: rtl;
    background: #2a1a3d;
    background-attachment: fixed;
    color: #e0e0e0;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    padding: 40px 20px;
    box-sizing: border-box;
    position: relative;
  }

  body::before {
    content: '';
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: radial-gradient(circle at 20% 80%, rgba(120, 119, 198, 0.3) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(255, 119, 198, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 40% 40%, rgba(120, 219, 255, 0.1) 0%, transparent 50%);
    pointer-events: none;
    z-index: -1;
  }

  .main-container {
    background: rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(25px) saturate(180%);
    -webkit-backdrop-filter: blur(25px) saturate(180%);
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: 20px;
    padding: 50px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1);
    max-width: 600px;
    width: 100%;
    text-align: center;
    position: relative;
  }

  .form-group {
    margin-bottom: 30px;
  }

  label {
    margin-bottom: 10px;
    display: block;
  }

  input.form-control {
    padding: 15px;
    border-radius: 10px;
    background: rgba(255, 255, 255, 0.1);
    border: 1px solid rgba(255, 255, 255, 0.2);
    color: #ffffff;
    width: 100%;
  }

  button.btn-primary {
    padding: 15px 30px;
    background: rgba(138, 43, 226, 0.3);
    border-radius: 15px;
    transition: all 0.3s;
    margin-top: 20px;
  }

  button.btn-primary:hover {
    background: rgba(138, 43, 226, 0.5);
  }

  .back-button {
    padding: 14px 28px;
    font-size: 1rem;
    border-radius: 25px;
    border: 1px solid rgba(255, 255, 255, 0.2);
    background: rgba(138, 43, 226, 0.15);
    backdrop-filter: blur(15px) saturate(150%);
    -webkit-backdrop-filter: blur(15px) saturate(150%);
    color: #ffffff;
    cursor: pointer;
    transition: all 0.3s ease;
    outline: none;
    margin-bottom: 20px;
    display: inline-block;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.1);
  }

  .back-button:hover {
    background: rgba(138, 43, 226, 0.25);
    border-color: rgba(255, 255, 255, 0.3);
    transform: translateY(-3px);
    box-shadow: 0 6px 20px rgba(138, 43, 226, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.15);
  }

  .alert {
    margin-bottom: 30px;
    padding: 15px;
    border-radius: 10px;
  }

  @media (max-width: 768px) {
    .main-container {
      padding: 30px;
    }
    .form-group {
      margin-bottom: 20px;
    }
  }
</style>
</head>
<body>
<div class="main-container">
  <a href="/" class="back-button">بازگشت به صحفه اصلی 🔙</a>
  <% if (message) { %>
      <div class="alert alert-<%= alertType %>">
          <%= message %>
      </div>
  <% } %>
  <form method="POST" action="/configure_khaerj_server">
      <div class="form-group">
          <label>نام تانل نمونه : 6to4tunnel55</label>
          <input type="text" name="tunnel_name" class="form-control" required>
      </div>
      <div class="form-group">
          <label>آیپی سرور ایران : </label>
          <input type="text" name="remote_ip" class="form-control" required>
      </div>
      <div class="form-group">
          <label>آیپی سرور خارج : </label>
          <input type="text" name="local_ip" class="form-control" required>
      </div>
      <div class="form-group">
          <label>آدرس ipv6 نمونه : fde6:84c6:1887::2 </label>
          <input type="text" name="ipv6_addr" class="form-control" required>
      </div>
      <div class="form-group">
          <label>ساب‌نت IPv6 نمونه : fde6:84c6:1887::/64 </label>
          <input type="text" name="ipv6_subnet" class="form-control" required>
      </div>
      <button type="submit" class="btn btn-primary">ارسـال 📤</button>
  </form>
</div>
</body>
</html>
EOF

    # Create gost EJS template
# Replace the entire cat <<EOF block for "$TEMPLATES_DIR/gost.ejs" with this:
cat <<EOF | sudo tee "$TEMPLATES_DIR/gost.ejs" >/dev/null || { echo -e "${RED}Failed to create gost.ejs${NC}"; exit 1; }
<!DOCTYPE html>
<html lang="fa">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Gost Tunnel Configuration</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  /* Custom Font: Vazirmatn */
  @font-face {
    font-family: "Vazirmatn";
    src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Regular.woff2") format("woff2");
    font-weight: normal;
    font-style: normal;
    font-display: swap;
  }
  @font-face {
    font-family: "Vazirmatn";
    src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Bold.woff2") format("woff2");
    font-weight: bold;
    font-style: normal;
    font-display: swap;
  }

  body {
    font-family: "Vazirmatn", sans-serif;
    direction: rtl;
    background: #2a1a3d;
    background-attachment: fixed;
    color: #e0e0e0;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    padding: 40px 20px;
    box-sizing: border-box;
    position: relative;
  }

  body::before {
    content: '';
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: radial-gradient(circle at 20% 80%, rgba(120, 119, 198, 0.3) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(255, 119, 198, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 40% 40%, rgba(120, 219, 255, 0.1) 0%, transparent 50%);
    pointer-events: none;
    z-index: -1;
  }

  .main-container {
    background: rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(25px) saturate(180%);
    -webkit-backdrop-filter: blur(25px) saturate(180%);
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: 20px;
    padding: 40px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1);
    max-width: 600px;
    width: 100%;
    text-align: center;
    position: relative;
  }

  .button-container {
    display: flex;
    flex-direction: column;
    gap: 20px;
    margin-bottom: 30px;
    margin-top: 20px;
  }

  .menu-button {
    padding: 18px 35px;
    font-size: 1.1rem;
    border-radius: 30px;
    border: 1px solid rgba(255, 255, 255, 0.15);
    background: rgba(255, 255, 255, 0.08);
    backdrop-filter: blur(20px) saturate(150%);
    -webkit-backdrop-filter: blur(20px) saturate(150%);
    color: #ffffff;
    cursor: pointer;
    transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
    outline: none;
    text-align: center;
    width: 100%;
    position: relative;
    overflow: hidden;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.1);
  }

  .menu-button::before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.1), transparent);
    transition: left 0.6s;
  }

  .menu-button:hover::before,
  .menu-button.active::before {
    left: 100%;
  }

  .menu-button:hover,
  .menu-button.active {
    background: rgba(255, 255, 255, 0.15);
    border-color: rgba(255, 255, 255, 0.3);
    transform: translateY(-5px) scale(1.02);
    box-shadow: 0 8px 30px rgba(138, 43, 226, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.2);
  }

  .menu-button:focus {
    border-color: rgba(255, 255, 255, 0.4);
    box-shadow: 0 0 0 4px rgba(138, 43, 226, 0.3), 0 8px 30px rgba(138, 43, 226, 0.2);
  }

  .menu-button.btn-danger {
    background: rgba(220, 53, 69, 0.3);
  }

  .menu-button.btn-danger:hover {
    background: rgba(220, 53, 69, 0.5);
  }

  .back-button {
    padding: 14px 28px;
    font-size: 1rem;
    border-radius: 25px;
    border: 1px solid rgba(255, 255, 255, 0.2);
    background: rgba(138, 43, 226, 0.15);
    backdrop-filter: blur(15px) saturate(150%);
    -webkit-backdrop-filter: blur(15px) saturate(150%);
    color: #ffffff;
    cursor: pointer;
    transition: all 0.3s ease;
    outline: none;
    margin-bottom: 20px;
    display: inline-block;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.1);
  }

  .back-button:hover {
    background: rgba(138, 43, 226, 0.25);
    border-color: rgba(255, 255, 255, 0.3);
    transform: translateY(-3px);
    box-shadow: 0 6px 20px rgba(138, 43, 226, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.15);
  }

  .alert {
    margin-bottom: 20px;
    padding: 15px;
    border-radius: 10px;
  }

  @media (max-width: 768px) {
    .main-container {
      padding: 25px;
    }
    .menu-button {
      padding: 15px 25px;
      font-size: 1rem;
      border-radius: 25px;
    }
  }
</style>
</head>
<body>
<div class="main-container">
  <a href="/" class="back-button">بازگشت به صحفه اصلی 🔙</a>
  <% if (message) { %>
      <div class="alert alert-<%= alertType %>">
          <%= message %>
      </div>
  <% } %>
  <div class="button-container">
    <a href="/install_gost_page" class="menu-button">نصب تانل گاست 👻</a>
    <a href="/gost_status_page" class="menu-button">وضعیت تانل گاست ⁉️</a>
    <a href="/add_new_ipv6_page" class="menu-button">افزودن IPv6 جدید ➕</a>
    <a href="/restart_tunnel_page" class="menu-button">راه‌اندازی مجدد تانل ♻️</a>
    <a href="/uninstall_gost_page" class="menu-button btn-danger">حذف تانل گاست 🗑</a>
  </div>
</div>
</body>
</html>
EOF

    # Create install_gost EJS template

# Replace the entire cat <<EOF block for "$TEMPLATES_DIR/install_gost.ejs" with this:
# Replace the entire cat <<EOF block for "$TEMPLATES_DIR/install_gost.ejs" with this:

# Replace the entire cat <<EOF block for "$TEMPLATES_DIR/install_gost.ejs" with this in install2.sh:
cat <<'EOF' | sudo tee "$TEMPLATES_DIR/install_gost.ejs" >/dev/null || { echo -e "${RED}Failed to create install_gost.ejs${NC}"; exit 1; }
<!DOCTYPE html>
<html lang="fa">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Install Gost</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  @font-face {
    font-family: "Vazirmatn";
    src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Regular.woff2") format("woff2");
    font-weight: normal;
    font-style: normal;
    font-display: swap;
  }
  @font-face {
    font-family: "Vazirmatn";
    src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Bold.woff2") format("woff2");
    font-weight: bold;
    font-style: normal;
    font-display: swap;
  }

  body {
    font-family: "Vazirmatn", sans-serif;
    direction: rtl;
    background: #2a1a3d;
    background-attachment: fixed;
    color: #e0e0e0;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    padding: 40px 20px;
    box-sizing: border-box;
    position: relative;
  }

  body::before {
    content: '';
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: radial-gradient(circle at 20% 80%, rgba(120, 119, 198, 0.3) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(255, 119, 198, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 40% 40%, rgba(120, 219, 255, 0.1) 0%, transparent 50%);
    pointer-events: none;
    z-index: -1;
  }

  .main-container {
    background: rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(25px) saturate(180%);
    -webkit-backdrop-filter: blur(25px) saturate(180%);
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: 20px;
    padding: 50px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1);
    max-width: 600px;
    width: 100%;
    text-align: center;
    position: relative;
  }

  .form-group {
    margin-bottom: 30px;
  }

  label {
    margin-bottom: 10px;
    display: block;
  }

  input.form-control {
    padding: 15px;
    border-radius: 10px;
    background: rgba(255, 255, 255, 0.1);
    border: 1px solid rgba(255, 255, 255, 0.2);
    color: #ffffff;
    width: 100%;
  }

  select.form-control {
    padding: 15px;
    border-radius: 10px;
    background: rgba(255, 255, 255, 0.1);
    border: 1px solid rgba(255, 255, 255, 0.2);
    color: #ffffff;
    width: 100%;
    appearance: none;
    background-image: none;
  }

  select.form-control option {
    background: #2a1a3d;
    color: #e0e0e0;
  }

  button.btn-primary {
    padding: 15px 30px;
    background: rgba(138, 43, 226, 0.3);
    border-radius: 15px;
    transition: all 0.3s;
    margin-top: 20px;
  }

  button.btn-primary:hover {
    background: rgba(138, 43, 226, 0.5);
  }

  .back-button {
    padding: 14px 28px;
    font-size: 1rem;
    border-radius: 25px;
    border: 1px solid rgba(255, 255, 255, 0.2);
    background: rgba(138, 43, 226, 0.15);
    backdrop-filter: blur(15px) saturate(150%);
    -webkit-backdrop-filter: blur(15px) saturate(150%);
    color: #ffffff;
    cursor: pointer;
    transition: all 0.3s ease;
    outline: none;
    margin-bottom: 20px;
    display: inline-block;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.1);
  }

  .back-button:hover {
    background: rgba(138, 43, 226, 0.25);
    border-color: rgba(255, 255, 255, 0.3);
    transform: translateY(-3px);
    box-shadow: 0 6px 20px rgba(138, 43, 226, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.15);
  }

  .alert {
    margin-bottom: 30px;
    padding: 15px;
    border-radius: 10px;
  }

  @media (max-width: 768px) {
    .main-container {
      padding: 30px;
    }
    .form-group {
      margin-bottom: 20px;
    }
  }
</style>
</head>
<body>
<div class="main-container">
  <a href="/gost" class="back-button">بازگشت به صحفه پیکربندی 🔙</a>
  <% if (message) { %>
      <div class="alert alert-<%= alertType %>">
          <%= message %>
      </div>
  <% } %>
  <form method="POST" action="/install_gost">
      <div class="form-group">
          <label>وارد کردن ipv6 لوکال پنل ( جهت مولتی لوکیشن با کاما وارد کنید )</label>
          <input type="text" name="panel_ips" class="form-control" required>
      </div>
      <div class="form-group">
          <label>پورت‌ پنل ( جهت مولتی لوکیشن بودن با کاما وارد کنید )</label>
          <input type="text" name="panel_ports" class="form-control" required>
      </div>
      <div class="form-group">
          <label>وارد کردن ipv6 لوکال اینباند / کانفیگ ( جهت مولتی لوکیشن با کاما وارد کنید )</label>
          <input type="text" name="inbound_ips" class="form-control">
      </div>
      <div class="form-group">
          <label>پورت‌های کانفیگ / اینباند (جهت مولتی لوکیشن بودن با کاما وارد کنید)</label>
          <input type="text" name="inbound_ports" class="form-control">
      </div>
      <div class="form-group">
          <label>پروتکل :</label>
          <select name="protocol_option" class="form-control" required onchange="this.style.color = '#ffffff'; this.selectedOptions[0].style.color = '#ffffff';">
              <option value="1" selected>TCP</option>
              <option value="2">UDP</option>
              <option value="3">هر دو TCP و UDP</option>
          </select>
      </div>
      <button type="submit" class="btn btn-primary">نـصـب 📲</button>
  </form>
  <script>
    document.addEventListener('DOMContentLoaded', function() {
        const panelIpInput = document.querySelector('input[name="panel_ips"]');
        const form = document.querySelector('form');

        panelIpInput.addEventListener('input', function() {
            let panel_ips = this.value.split(',').filter(ip => ip.trim());
            let existingRandomGroups = form.querySelectorAll('.form-group');
            existingRandomGroups.forEach(group => {
                if (group.querySelector('label') && group.querySelector('label').textContent.startsWith(' یک پورت رندوم وارد کنید ')) {
                    group.remove();
                }
            });
            panel_ips.forEach((ip, i) => {
                if (ip.trim()) {
                    let div = document.createElement('div');
                    div.className = 'form-group';
                    div.innerHTML = "<label> یک پورت رندوم وارد کنید " + ip.trim() + ":</label><input type='number' name='panel_random_port_" + i + "' class='form-control' min='1' max='65535' required>";
                    form.insertBefore(div, form.querySelector('button'));
                }
            });
        });
    });
  </script>
</body>
</html>
EOF

    # Create gost_status EJS template

# Replace the entire cat <<EOF block for "$TEMPLATES_DIR/gost_status.ejs" with this:
cat <<EOF | sudo tee "$TEMPLATES_DIR/gost_status.ejs" >/dev/null || { echo -e "${RED}Failed to create gost_status.ejs${NC}"; exit 1; }
<!DOCTYPE html>
<html lang="fa">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Gost Status</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  /* Custom Font: Vazirmatn */
  @font-face {
    font-family: "Vazirmatn";
    src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Regular.woff2") format("woff2");
    font-weight: normal;
    font-style: normal;
    font-display: swap;
  }
  @font-face {
    font-family: "Vazirmatn";
    src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Bold.woff2") format("woff2");
    font-weight: bold;
    font-style: normal;
    font-display: swap;
  }

  body {
    font-family: "Vazirmatn", sans-serif;
    direction: rtl;
    background: #2a1a3d;
    background-attachment: fixed;
    color: #e0e0e0;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    padding: 40px 20px;
    box-sizing: border-box;
    position: relative;
  }

  body::before {
    content: '';
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: radial-gradient(circle at 20% 80%, rgba(120, 119, 198, 0.3) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(255, 119, 198, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 40% 40%, rgba(120, 219, 255, 0.1) 0%, transparent 50%);
    pointer-events: none;
    z-index: -1;
  }

  .main-container {
    background: rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(25px) saturate(180%);
    -webkit-backdrop-filter: blur(25px) saturate(180%);
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: 20px;
    padding: 40px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1);
    max-width: 600px;
    width: 100%;
    text-align: center;
    position: relative;
  }

  .form-group {
    margin-bottom: 20px;
  }

  button.btn-primary {
    padding: 12px 25px;
    background: rgba(138, 43, 226, 0.3);
    border-radius: 15px;
    transition: all 0.3s;
  }

  button.btn-primary:hover {
    background: rgba(138, 43, 226, 0.5);
  }

  .back-button {
    padding: 14px 28px;
    font-size: 1rem;
    border-radius: 25px;
    border: 1px solid rgba(255, 255, 255, 0.2);
    background: rgba(138, 43, 226, 0.15);
    backdrop-filter: blur(15px) saturate(150%);
    -webkit-backdrop-filter: blur(15px) saturate(150%);
    color: #ffffff;
    cursor: pointer;
    transition: all 0.3s ease;
    outline: none;
    margin-bottom: 40px;
    display: inline-block;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.1);
  }

  .back-button:hover {
    background: rgba(138, 43, 226, 0.25);
    border-color: rgba(255, 255, 255, 0.3);
    transform: translateY(-3px);
    box-shadow: 0 6px 20px rgba(138, 43, 226, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.15);
  }

  .alert {
    margin-bottom: 20px;
    padding: 15px;
    border-radius: 10px;
  }

  .status-text {
    font-size: 1.2rem;
    font-weight: bold;
    margin-bottom: 20px;
    margin-top: 0;
  }

  @media (max-width: 768px) {
    .main-container {
      padding: 25px;
    }
  }
</style>
</head>
<body>
<div class="main-container">
  <a href="/gost" class="back-button">بازگشت به صحفه پیکربندی 🔙</a>
  <% if (message) { %>
      <div class="alert alert-<%= alertType %>">
          <%= message %>
      </div>
  <% } %>
  <% if (status) { %>
      <div class="alert alert-<%= status === 'Running' ? 'success' : status === 'Stopped' ? 'warning' : 'danger' %>">
          وضعیت سرویس Gost: <%= status %>
      </div>
  <% } else { %>
      <p class="status-text">برای بررسی وضعیت، روی دکمه زیر کلیک کنید.</p>
  <% } %>
  <form method="POST" action="/gost_status">
      <button type="submit" class="btn btn-primary">بررسی وضعیت 🔍</button>
  </form>
</div>
</body>
</html>
EOF

    # Create add_new_ipv6 EJS template

# Replace the entire cat <<EOF block for "$TEMPLATES_DIR/add_new_ipv6.ejs" with this:
cat <<EOF | sudo tee "$TEMPLATES_DIR/add_new_ipv6.ejs" >/dev/null || { echo -e "${RED}Failed to create add_new_ipv6.ejs${NC}"; exit 1; }
<!DOCTYPE html>
<html lang="fa">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Add New IPv6</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  /* Custom Font: Vazirmatn */
  @font-face {
    font-family: "Vazirmatn";
    src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Regular.woff2") format("woff2");
    font-weight: normal;
    font-style: normal;
    font-display: swap;
  }
  @font-face {
    font-family: "Vazirmatn";
    src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Bold.woff2") format("woff2");
    font-weight: bold;
    font-style: normal;
    font-display: swap;
  }

  body {
    font-family: "Vazirmatn", sans-serif;
    direction: rtl;
    background: #2a1a3d;
    background-attachment: fixed;
    color: #e0e0e0;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    padding: 40px 20px;
    box-sizing: border-box;
    position: relative;
  }

  body::before {
    content: '';
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: radial-gradient(circle at 20% 80%, rgba(120, 119, 198, 0.3) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(255, 119, 198, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 40% 40%, rgba(120, 219, 255, 0.1) 0%, transparent 50%);
    pointer-events: none;
    z-index: -1;
  }

  .main-container {
    background: rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(25px) saturate(180%);
    -webkit-backdrop-filter: blur(25px) saturate(180%);
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: 20px;
    padding: 40px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1);
    max-width: 600px;
    width: 100%;
    text-align: center;
    position: relative;
  }

  .form-group {
    margin-bottom: 50px; /* افزایش فاصله بین متن‌ها */
  }

  label {
    margin-bottom: 20px; /* افزایش فاصله زیر متن‌های لیبل */
    display: block;
  }

  input.form-control, select.form-control {
    padding: 15px;
    border-radius: 10px;
    background: rgba(255, 255, 255, 0.1);
    border: 1px solid rgba(255, 255, 255, 0.2);
    color: #ffffff;
    width: 100%;
  }

  select.form-control {
    appearance: none;
    -webkit-appearance: none;
    -moz-appearance: none;
    background-image: url('data:image/svg+xml;utf8,<svg fill="white" height="24" viewBox="0 0 24 24" width="24" xmlns="http://www.w3.org/2000/svg"><path d="M7 10l5 5 5-5z"/></svg>');
    background-repeat: no-repeat;
    background-position-x: 98%;
    background-position-y: center;
  }

  select.form-control option {
    background: #2a1a3d;
    color: #e0e0e0;
  }

  button.btn-primary {
    padding: 15px 30px;
    background: rgba(138, 43, 226, 0.3);
    border-radius: 15px;
    transition: all 0.3s;
    margin-top: 40px;
    margin-bottom: 50px;
  }

  button.btn-primary:hover {
    background: rgba(138, 43, 226, 0.5);
  }

  .back-button {
    padding: 14px 28px;
    font-size: 1rem;
    border-radius: 25px;
    border: 1px solid rgba(255, 255, 255, 0.2);
    background: rgba(138, 43, 226, 0.15);
    backdrop-filter: blur(15px) saturate(150%);
    -webkit-backdrop-filter: blur(15px) saturate(150%);
    color: #ffffff;
    cursor: pointer;
    transition: all 0.3s ease;
    outline: none;
    margin-bottom: 40px;
    display: inline-block;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.1);
  }

  .back-button:hover {
    background: rgba(138, 43, 226, 0.25);
    border-color: rgba(255, 255, 255, 0.3);
    transform: translateY(-3px);
    box-shadow: 0 6px 20px rgba(138, 43, 226, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.15);
  }

  .alert {
    margin-bottom: 25px;
    padding: 15px;
    border-radius: 10px;
  }

  h3 {
    margin-bottom: 40px;
    margin-top: 50px;
  }

  @media (max-width: 768px) {
    .main-container {
      padding: 25px;
    }
    .form-group {
      margin-bottom: 35px;
    }
    label {
      margin-bottom: 15px;
    }
  }
</style>
</head>
<body>
<div class="main-container">
  <a href="/gost" class="back-button">بازگشت به صحفه پیکربندی 🔙</a>
  <% if (message) { %>
      <div class="alert alert-<%= alertType %>">
          <%= message %>
      </div>
  <% } %>

  <!-- Panel Form -->
  <form method="POST" action="/add_new_ipv6_panel">
      <div class="form-group">
          <label>IPv6 پنل:</label>
          <input type="text" name="panel_ip" class="form-control" required>
      </div>
      <div class="form-group">
          <label>پورت پنل : </label>
          <input type="text" name="panel_port" class="form-control" required>
      </div>
      <div class="form-group">
          <label>پورت رندوم:</label>
          <input type="text" name="panel_random_port" class="form-control" required>
      </div>
      <div class="form-group">
          <label>پروتکل:</label>
          <select name="protocol" class="form-control" required>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
          </select>
      </div>
      <button type="submit" class="btn btn-primary">افزودن پنل ➕</button>
  </form>

  <!-- Inbound Form -->
  <form method="POST" action="/add_new_ipv6_inbound">
      <div class="form-group">
          <label>IPv6 اینباند:</label>
          <input type="text" name="inbound_ip" class="form-control" required>
      </div>
      <div class="form-group">
          <label>پورت اینباند:</label>
          <input type="text" name="inbound_port" class="form-control" required>
      </div>
      <div class="form-group">
          <label>پروتکل:</label>
          <select name="protocol" class="form-control" required>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
          </select>
      </div>
      <button type="submit" class="btn btn-primary">افزودن اینباند ➕</button>
  </form>
</div>
</body>
</html>
EOF

    # Create restart_tunnel EJS template


# Replace the entire cat <<EOF block for "$TEMPLATES_DIR/restart_tunnel.ejs" with this:
cat <<EOF | sudo tee "$TEMPLATES_DIR/restart_tunnel.ejs" >/dev/null || { echo -e "${RED}Failed to create restart_tunnel.ejs${NC}"; exit 1; }
<!DOCTYPE html>
<html lang="fa">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Restart Tunnel</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  /* Custom Font: Vazirmatn */
  @font-face {
    font-family: "Vazirmatn";
    src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Regular.woff2") format("woff2");
    font-weight: normal;
    font-style: normal;
    font-display: swap;
  }
  @font-face {
    font-family: "Vazirmatn";
    src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Bold.woff2") format("woff2");
    font-weight: bold;
    font-style: normal;
    font-display: swap;
  }

  body {
    font-family: "Vazirmatn", sans-serif;
    direction: rtl;
    background: #2a1a3d;
    background-attachment: fixed;
    color: #e0e0e0;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    padding: 40px 20px;
    box-sizing: border-box;
    position: relative;
  }

  body::before {
    content: '';
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: radial-gradient(circle at 20% 80%, rgba(120, 119, 198, 0.3) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(255, 119, 198, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 40% 40%, rgba(120, 219, 255, 0.1) 0%, transparent 50%);
    pointer-events: none;
    z-index: -1;
  }

  .main-container {
    background: rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(25px) saturate(180%);
    -webkit-backdrop-filter: blur(25px) saturate(180%);
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: 20px;
    padding: 40px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1);
    max-width: 600px;
    width: 100%;
    text-align: center;
    position: relative;
  }

  button.btn-primary {
    padding: 12px 25px;
    background: rgba(138, 43, 226, 0.3);
    border-radius: 15px;
    transition: all 0.3s;
  }

  button.btn-primary:hover {
    background: rgba(138, 43, 226, 0.5);
  }

  .back-button {
    padding: 14px 28px;
    font-size: 1rem;
    border-radius: 25px;
    border: 1px solid rgba(255, 255, 255, 0.2);
    background: rgba(138, 43, 226, 0.15);
    backdrop-filter: blur(15px) saturate(150%);
    -webkit-backdrop-filter: blur(15px) saturate(150%);
    color: #ffffff;
    cursor: pointer;
    transition: all 0.3s ease;
    outline: none;
    margin-bottom: 20px;
    display: inline-block;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.1);
  }

  .back-button:hover {
    background: rgba(138, 43, 226, 0.25);
    border-color: rgba(255, 255, 255, 0.3);
    transform: translateY(-3px);
    box-shadow: 0 6px 20px rgba(138, 43, 226, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.15);
  }

  .alert {
    margin-bottom: 20px;
    padding: 15px;
    border-radius: 10px;
  }

  @media (max-width: 768px) {
    .main-container {
      padding: 25px;
    }
  }
</style>
</head>
<body>
<div class="main-container">
  <a href="/gost" class="back-button">بازگشت به صحفه پیکربندی 🔙</a>
  <% if (message) { %>
      <div class="alert alert-<%= alertType %>">
          <%= message %>
      </div>
  <% } %>
  <form method="POST" action="/restart_tunnel">
      <button type="submit" class="btn btn-primary">راه‌اندازی مجدد ♻️</button>
  </form>
</div>
</body>
</html>
EOF


    # Create uninstall_gost EJS template

# Replace the entire cat <<EOF block for "$TEMPLATES_DIR/uninstall_gost.ejs" with this:
cat <<EOF | sudo tee "$TEMPLATES_DIR/uninstall_gost.ejs" >/dev/null || { echo -e "${RED}Failed to create uninstall_gost.ejs${NC}"; exit 1; }
<!DOCTYPE html>
<html lang="fa">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Uninstall Gost</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  /* Custom Font: Vazirmatn */
  @font-face {
    font-family: "Vazirmatn";
    src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Regular.woff2") format("woff2");
    font-weight: normal;
    font-style: normal;
    font-display: swap;
  }
  @font-face {
    font-family: "Vazirmatn";
    src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Bold.woff2") format("woff2");
    font-weight: bold;
    font-style: normal;
    font-display: swap;
  }

  body {
    font-family: "Vazirmatn", sans-serif;
    direction: rtl;
    background: #2a1a3d;
    background-attachment: fixed;
    color: #e0e0e0;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    padding: 40px 20px;
    box-sizing: border-box;
    position: relative;
  }

  body::before {
    content: '';
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: radial-gradient(circle at 20% 80%, rgba(120, 119, 198, 0.3) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(255, 119, 198, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 40% 40%, rgba(120, 219, 255, 0.1) 0%, transparent 50%);
    pointer-events: none;
    z-index: -1;
  }

  .main-container {
    background: rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(25px) saturate(180%);
    -webkit-backdrop-filter: blur(25px) saturate(180%);
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: 20px;
    padding: 40px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1);
    max-width: 600px;
    width: 100%;
    text-align: center;
    position: relative;
  }

  button.btn-danger {
    padding: 12px 25px;
    background: rgba(220, 53, 69, 0.3);
    border-radius: 15px;
    transition: all 0.3s;
  }

  button.btn-danger:hover {
    background: rgba(220, 53, 69, 0.5);
  }

  .back-button {
    padding: 14px 28px;
    font-size: 1rem;
    border-radius: 25px;
    border: 1px solid rgba(255, 255, 255, 0.2);
    background: rgba(138, 43, 226, 0.15);
    backdrop-filter: blur(15px) saturate(150%);
    -webkit-backdrop-filter: blur(15px) saturate(150%);
    color: #ffffff;
    cursor: pointer;
    transition: all 0.3s ease;
    outline: none;
    margin-bottom: 20px;
    display: inline-block;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.1);
  }

  .back-button:hover {
    background: rgba(138, 43, 226, 0.25);
    border-color: rgba(255, 255, 255, 0.3);
    transform: translateY(-3px);
    box-shadow: 0 6px 20px rgba(138, 43, 226, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.15);
  }

  .alert {
    margin-bottom: 20px;
    padding: 15px;
    border-radius: 10px;
  }

  @media (max-width: 768px) {
    .main-container {
      padding: 25px;
    }
  }
</style>
</head>
<body>
<div class="main-container">
  <a href="/gost" class="back-button">بازگشت به صحفه پیکربندی 🔙</a>
  <% if (message) { %>
      <div class="alert alert-<%= alertType %>">
          <%= message %>
      </div>
  <% } %>
  <form method="POST" action="/uninstall_gost">
      <button type="submit" class="btn btn-danger">حذف تانل گاست 🗑</button>
  </form>
</div>
</body>
</html>
EOF

    # Create test_ping EJS template

# Replace the entire cat <<EOF block for "$TEMPLATES_DIR/test_ping_page.ejs" with this:
cat <<EOF | sudo tee "$TEMPLATES_DIR/test_ping_page.ejs" >/dev/null || { echo -e "${RED}Failed to create test_ping_page.ejs${NC}"; exit 1; }
<!DOCTYPE html>
<html lang="fa">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Test Ping</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  @font-face {
    font-family: "Vazirmatn";
    src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Regular.woff2") format("woff2");
    font-weight: normal;
    font-style: normal;
    font-display: swap;
  }
  @font-face {
    font-family: "Vazirmatn";
    src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Bold.woff2") format("woff2");
    font-weight: bold;
    font-style: normal;
    font-display: swap;
  }

  body {
    font-family: "Vazirmatn", sans-serif;
    direction: rtl;
    background: #2a1a3d;
    background-attachment: fixed;
    color: #e0e0e0;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    padding: 40px 20px;
    box-sizing: border-box;
    position: relative;
  }

  body::before {
    content: '';
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: radial-gradient(circle at 20% 80%, rgba(120, 119, 198, 0.3) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(255, 119, 198, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 40% 40%, rgba(120, 219, 255, 0.1) 0%, transparent 50%);
    pointer-events: none;
    z-index: -1;
  }

  .main-container {
    background: rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(25px) saturate(180%);
    -webkit-backdrop-filter: blur(25px) saturate(180%);
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: 20px;
    padding: 50px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1);
    max-width: 600px;
    width: 100%;
    text-align: center;
    position: relative;
  }

  .form-group {
    margin-bottom: 30px;
  }

  label {
    margin-bottom: 10px;
    display: block;
  }

  input.form-control {
    padding: 15px;
    border-radius: 10px;
    background: rgba(255, 255, 255, 0.1);
    border: 1px solid rgba(255, 255, 255, 0.2);
    color: #ffffff;
    width: 100%;
  }

  button.btn-primary {
    padding: 15px 30px;
    background: rgba(138, 43, 226, 0.3);
    border-radius: 15px;
    transition: all 0.3s;
    margin-top: 20px;
  }

  button.btn-primary:hover {
    background: rgba(138, 43, 226, 0.5);
  }

  .back-button {
    padding: 14px 28px;
    font-size: 1rem;
    border-radius: 25px;
    border: 1px solid rgba(255, 255, 255, 0.2);
    background: rgba(138, 43, 226, 0.15);
    backdrop-filter: blur(15px) saturate(150%);
    -webkit-backdrop-filter: blur(15px) saturate(150%);
    color: #ffffff;
    cursor: pointer;
    transition: all 0.3s ease;
    outline: none;
    margin-bottom: 20px;
    display: inline-block;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.1);
  }

  .back-button:hover {
    background: rgba(138, 43, 226, 0.25);
    border-color: rgba(255, 255, 255, 0.3);
    transform: translateY(-3px);
    box-shadow: 0 6px 20px rgba(138, 43, 226, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.15);
  }

  .alert {
    margin-bottom: 30px;
    padding: 15px;
    border-radius: 10px;
  }

  @media (max-width: 768px) {
    .main-container {
      padding: 30px;
    }
    .form-group {
      margin-bottom: 20px;
    }
  }
</style>
</head>
<body>
<div class="main-container">
  <a href="/" class="back-button">بازگشت به صحفه اصلی 🔙</a>
  <% if (message) { %>
      <div class="alert alert-<%= alertType %>">
          <%= message %>
      </div>
  <% } %>
  <form method="POST" action="/test_ping">
      <div class="form-group">
          <label>آدرس ipv6  برای تست پـیـنـگ نمونه : fde6:84c6:1887::1</label>
          <input type="text" name="ping_address" class="form-control" required>
      </div>
      <button type="submit" class="btn btn-primary">تـسـت پـیـنـگ</button>
  </form>
</div>
</body>
</html>
EOF

    # Create delete_tunnel EJS template
# Replace the entire cat <<EOF block for "$TEMPLATES_DIR/delete_tunnel_page.ejs" with this:
cat <<EOF | sudo tee "$TEMPLATES_DIR/delete_tunnel_page.ejs" >/dev/null || { echo -e "${RED}Failed to create delete_tunnel_page.ejs${NC}"; exit 1; }
<!DOCTYPE html>
<html lang="fa">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Delete Tunnel</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  @font-face {
    font-family: "Vazirmatn";
    src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Regular.woff2") format("woff2");
    font-weight: normal;
    font-style: normal;
    font-display: swap;
  }
  @font-face {
    font-family: "Vazirmatn";
    src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Bold.woff2") format("woff2");
    font-weight: bold;
    font-style: normal;
    font-display: swap;
  }

  body {
    font-family: "Vazirmatn", sans-serif;
    direction: rtl;
    background: #2a1a3d;
    background-attachment: fixed;
    color: #e0e0e0;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    padding: 40px 20px;
    box-sizing: border-box;
    position: relative;
  }

  body::before {
    content: '';
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: radial-gradient(circle at 20% 80%, rgba(120, 119, 198, 0.3) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(255, 119, 198, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 40% 40%, rgba(120, 219, 255, 0.1) 0%, transparent 50%);
    pointer-events: none;
    z-index: -1;
  }

  .main-container {
    background: rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(25px) saturate(180%);
    -webkit-backdrop-filter: blur(25px) saturate(180%);
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: 20px;
    padding: 50px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1);
    max-width: 600px;
    width: 100%;
    text-align: center;
    position: relative;
  }

  .form-group {
    margin-bottom: 30px;
  }

 select.form-control {
    padding: 15px;
    border-radius: 10px;
    background: rgba(255, 255, 255, 0.1);
    border: 1px solid rgba(255, 255, 255, 0.2);
    color: #ffffff;
    width: 100%;
    appearance: none;
    background-image: none;
  }

  select.form-control option {
    background: #2a1a3d;
    color: #e0e0e0;
  }

  button.btn-danger {
    padding: 15px 30px;
    background: rgba(220, 53, 69, 0.3);
    border-radius: 15px;
    transition: all 0.3s;
    margin-top: 20px;
  }

  button.btn-danger:hover {
    background: rgba(220, 53, 69, 0.5);
  }

  .back-button {
    padding: 14px 28px;
    font-size: 1rem;
    border-radius: 25px;
    border: 1px solid rgba(255, 255, 255, 0.2);
    background: rgba(138, 43, 226, 0.15);
    backdrop-filter: blur(15px) saturate(150%);
    -webkit-backdrop-filter: blur(15px) saturate(150%);
    color: #ffffff;
    cursor: pointer;
    transition: all 0.3s ease;
    outline: none;
    margin-bottom: 20px;
    display: inline-block;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.1);
  }

  .back-button:hover {
    background: rgba(138, 43, 226, 0.25);
    border-color: rgba(255, 255, 255, 0.3);
    transform: translateY(-3px);
    box-shadow: 0 6px 20px rgba(138, 43, 226, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.15);
  }

  .alert {
    margin-bottom: 30px;
    padding: 15px;
    border-radius: 10px;
  }

  @media (max-width: 768px) {
    .main-container {
      padding: 30px;
    }
    .form-group {
      margin-bottom: 20px;
    }
  }
</style>
</head>
<body>
<div class="main-container">
  <a href="/" class="back-button">بازگشت به صحفه اصلی 🔙</a>
  <% if (message) { %>
      <div class="alert alert-<%= alertType %>">
          <%= message %>
      </div>
  <% } %>
  <form method="POST" action="/delete_tunnel">
      <div class="form-group">
          <label>انتخاب تـانـل برای حـذف : </label>
          <select name="tunnel_name" class="form-control" required>
              <% tunnels.forEach(tunnel => { %>
                  <option value="<%= tunnel %>"><%= tunnel %></option>
              <% }); %>
          </select>
      </div>
      <button type="submit" class="btn btn-danger">حـذف تـانل 🗑</button>
  </form>
</div>
</body>
</html>
EOF

    # Create delete_netplan EJS template
# Replace the entire cat <<EOF block for "$TEMPLATES_DIR/delete_netplan.ejs" with this:
cat <<EOF | sudo tee "$TEMPLATES_DIR/delete_netplan.ejs" >/dev/null || { echo -e "${RED}Failed to create delete_netplan.ejs${NC}"; exit 1; }
<!DOCTYPE html>
<html lang="fa">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Delete Netplan Configuration</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  /* Custom Font: Vazirmatn */
  @font-face {
    font-family: "Vazirmatn";
    src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Regular.woff2") format("woff2");
    font-weight: normal;
    font-style: normal;
    font-display: swap;
  }
  @font-face {
    font-family: "Vazirmatn";
    src: url("https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Bold.woff2") format("woff2");
    font-weight: bold;
    font-style: normal;
    font-display: swap;
  }

  body {
    font-family: "Vazirmatn", sans-serif;
    direction: rtl;
    background: #2a1a3d;
    background-attachment: fixed;
    color: #e0e0e0;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    padding: 40px 20px;
    box-sizing: border-box;
    position: relative;
  }

  body::before {
    content: '';
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: radial-gradient(circle at 20% 80%, rgba(120, 119, 198, 0.3) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(255, 119, 198, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 40% 40%, rgba(120, 219, 255, 0.1) 0%, transparent 50%);
    pointer-events: none;
    z-index: -1;
  }

  .main-container {
    background: rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(25px) saturate(180%);
    -webkit-backdrop-filter: blur(25px) saturate(180%);
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: 20px;
    padding: 40px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1);
    max-width: 600px;
    width: 100%;
    text-align: center;
    position: relative;
  }

  .form-group {
    margin-bottom: 20px;
  }

 select.form-control {
    padding: 15px;
    border-radius: 10px;
    background: rgba(255, 255, 255, 0.1);
    border: 1px solid rgba(255, 255, 255, 0.2);
    color: #ffffff;
    width: 100%;
    appearance: none;
    background-image: none;
  }

  select.form-control option {
    background: #2a1a3d;
    color: #e0e0e0;
  }

  button.btn-danger {
    padding: 12px 25px;
    background: rgba(220, 53, 69, 0.3);
    border-radius: 15px;
    transition: all 0.3s;
  }

  button.btn-danger:hover {
    background: rgba(220, 53, 69, 0.5);
  }

  .back-button {
    padding: 14px 28px;
    font-size: 1rem;
    border-radius: 25px;
    border: 1px solid rgba(255, 255, 255, 0.2);
    background: rgba(138, 43, 226, 0.15);
    backdrop-filter: blur(15px) saturate(150%);
    -webkit-backdrop-filter: blur(15px) saturate(150%);
    color: #ffffff;
    cursor: pointer;
    transition: all 0.3s ease;
    outline: none;
    margin-bottom: 20px;
    display: inline-block;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.1);
  }

  .back-button:hover {
    background: rgba(138, 43, 226, 0.25);
    border-color: rgba(255, 255, 255, 0.3);
    transform: translateY(-3px);
    box-shadow: 0 6px 20px rgba(138, 43, 226, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.15);
  }

  .alert {
    margin-bottom: 20px;
    padding: 15px;
    border-radius: 10px;
  }

  @media (max-width: 768px) {
    .main-container {
      padding: 25px;
    }
  }
</style>
</head>
<body>
<div class="main-container">
  <a href="/" class="back-button">بازگشت به صحفه اصلی 🔙</a>
  <% if (message) { %>
      <div class="alert alert-<%= alertType %>">
          <%= message %>
      </div>
  <% } %>
  <form method="POST" action="/delete_netplan">
      <div class="form-group">
          <label>انتخاب فایل نـت پـلـن : </label>
          <select name="netplan_file" class="form-control" required>
              <% netplans.forEach(netplan => { %>
                  <option value="<%= netplan %>"><%= netplan %></option>
              <% }); %>
          </select>
      </div>
      <button type="submit" class="btn btn-danger">حـذف 🗑</button>
  </form>
</div>
</body>
</html>
EOF



 

    # Create Python script for Gost update
cat <<'EOF' | sudo tee "/tmp/gost_update.py" >/dev/null || { echo -e "${RED}Failed to create gost_update.py${NC}"; exit 1; }
import os
import sys
import subprocess

def update_gost_service(new_lines_str):
    SERVICE_FILE = "/usr/lib/systemd/system/gost_0.service"

    if not os.path.exists(SERVICE_FILE):
        print("\033[31mError: Service file not found at /usr/lib/systemd/system/gost_0.service. Please run Gost Tunnel By IP6 first.\033[0m")
        sys.exit(1)

    if not os.access(SERVICE_FILE, os.W_OK):
        print(f"\033[31mError: No write permission for {SERVICE_FILE}. Please check permissions.\033[0m")
        sys.exit(1)

    new_lines = [line.strip() for line in new_lines_str.split('|') if line.strip()]
    if not new_lines:
        print("\033[31mError: No new lines provided.\033[0m")
        sys.exit(1)

    with open(SERVICE_FILE, 'r') as file:
        lines = file.readlines()

    new_content = []
    in_execstart = False
    new_line_added = False
    for line in lines:
        new_content.append(line.rstrip())
        if line.startswith("ExecStart=/usr/local/bin/gost \\"):
            in_execstart = True
            if not new_line_added and new_lines:
                new_content.append(f"    -L={new_lines[0]} \\")
                new_line_added = True
        elif in_execstart and (line.strip() == "" or (line.strip().startswith("-L=") and not line.endswith("\\"))):
            if new_line_added and len(new_lines) > 1:
                for i, new_line in enumerate(new_lines[1:], start=1):
                    formatted_line = f"    -L={new_line}"
                    new_content.append(formatted_line + " \\" if i < len(new_lines) - 1 else formatted_line)
            in_execstart = False

    if not new_line_added and new_lines:
        new_content = [
            "[Unit]",
            "Description=GO Simple Tunnel for Multiple External IPs",
            "After=network.target",
            "Wants=network.target",
            "",
            "[Service]",
            "Type=simple",
            'Environment="GOST_LOGGER_LEVEL=fatal"',
            "ExecStart=/usr/local/bin/gost \\"
        ]
        for i, new_line in enumerate(new_lines):
            formatted_line = f"    -L={new_line}"
            new_content.append(formatted_line + " \\" if i < len(new_lines) - 1 else formatted_line)
        new_content.append("")
        new_content.extend(["[Install]", "WantedBy=multi-user.target"])

    temp_file = "/tmp/gost_0.service.tmp"
    with open(temp_file, 'w') as file:
        for line in new_content:
            file.write(line + "\n")

    # استفاده از اسکریپت کمکی برای انتقال فایل
    subprocess.run(['sudo', '/usr/local/bin/move_gost_service.sh'], check=True)

    # اجرای دستورات با sudo برای اطمینان از دسترسی
    subprocess.run(['sudo', 'systemctl', 'daemon-reload'], check=True)
    subprocess.run(['sudo', 'systemctl', 'restart', 'gost_0.service'], check=True)

    print("\033[32mNew IPv6 configuration added successfully to gost_0.service.\033[0m")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        update_gost_service(sys.argv[1])
    else:
        print("\033[31mError: No new lines provided.\033[0m")
        sys.exit(1)
EOF
chmod +x "/tmp/gost_update.py" || { echo -e "${RED}Failed to set permissions on gost_update.py${NC}"; exit 1; }

    # Set permissions
    sudo chown -R www-data:www-data "$PROJECT_DIR" || { echo -e "${RED}Failed to set ownership${NC}"; exit 1; }
    sudo chmod -R 755 "$PROJECT_DIR" || { echo -e "${RED}Failed to set permissions${NC}"; exit 1; }
    sudo chmod 600 "$CONFIG_DIR/credentials.conf" || { echo -e "${RED}Failed to set permissions on credentials${NC}"; exit 1; }



# Configure sudoers for www-data
echo "www-data ALL=(ALL) NOPASSWD: /bin/mkdir, /bin/tee, /usr/bin/chown, /bin/chmod, /usr/bin/systemctl daemon-reload, /usr/bin/systemctl restart gost_0.service, /usr/bin/systemctl enable gost_0.service, /usr/bin/systemctl start gost_0.service, /usr/bin/systemctl status gost_0.service --no-pager, /usr/bin/apt, /bin/mv, /bin/rm, /bin/cat, /bin/sh, /usr/local/bin/move_gost_service.sh, /usr/bin/yum, /usr/sbin/netplan apply, /sbin/ip, /usr/bin/killall -9 gost, /usr/bin/systemctl stop sysctl-custom, /usr/bin/systemctl disable sysctl-custom" | sudo tee /etc/sudoers.d/6to4tunnel >/dev/null || {
    echo -e "${RED}Failed to create sudoers file${NC}"
    exit 1
}
sudo chmod 440 /etc/sudoers.d/6to4tunnel || {
    echo -e "${RED}Failed to set permissions on sudoers${NC}"
    exit 1
}

echo "www-data ALL=(ALL) NOPASSWD: /bin/mkdir, /bin/tee, /usr/bin/chown, /bin/chmod, /usr/bin/systemctl daemon-reload, /usr/bin/systemctl restart gost_0.service, /usr/bin/systemctl enable gost_0.service, /usr/bin/systemctl start gost_0.service, /usr/bin/systemctl status gost_0.service --no-pager, /usr/bin/apt, /bin/mv, /bin/rm, /bin/cat, /bin/sh, /usr/local/bin/move_gost_service.sh, /usr/bin/yum, /usr/sbin/netplan apply, /sbin/ip, /usr/bin/killall -9 gost, /usr/bin/systemctl stop sysctl-custom, /usr/bin/systemctl disable sysctl-custom" | sudo tee /etc/sudoers.d/6to4tunnel >/dev/null || {
    echo -e "${RED}Failed to create sudoers file${NC}"
    exit 1
}
sudo chmod 440 /etc/sudoers.d/6to4tunnel || {
    echo -e "${RED}Failed to set permissions on sudoers${NC}"
    exit 1
}

    # Create systemd service for Node.js
    NODE_PATH=$(which node)
    if [ -z "$NODE_PATH" ]; then
        echo -e "${RED}Node.js not found. Installation failed.${NC}"
        exit 1
    fi

    cat <<EOF | sudo tee /etc/systemd/system/6to4tunnel.service >/dev/null || { echo -e "${RED}Failed to create systemd service${NC}"; exit 1; }
[Unit]
Description=6to4 Tunnel Web App
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=$PROJECT_DIR
Environment="PATH=/usr/local/bin:/usr/bin:/bin:/home/$USER/.local/bin"
Environment="WEB_PORT=$WEB_PORT"
ExecStart=$NODE_PATH $PROJECT_DIR/app.js
Restart=always
RestartSec=3
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
EOF

    # Start and enable service
    sudo systemctl daemon-reload || { echo -e "${RED}Failed to reload systemd${NC}"; exit 1; }
    if ! sudo systemctl start 6to4tunnel; then
        echo -e "${RED}Failed to start 6to4tunnel service. Check logs:${NC}"
        sudo journalctl -u 6to4tunnel -n 50 --no-pager
        exit 1
    fi
    sudo systemctl enable 6to4tunnel || { echo -e "${RED}Failed to enable 6to4tunnel service${NC}"; exit 1; }

    # Check if service is running
    if sudo systemctl is-active --quiet 6to4tunnel; then
        echo -e "${GREEN}6to4tunnel service started successfully.${NC}"
    else
        echo -e "${RED}6to4tunnel service failed to start. Check logs:${NC}"
        sudo journalctl -u 6to4tunnel -n 50 --no-pager
        exit 1
    fi

    # Get server IP
    SERVER_IP=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d'/' -f1 | head -n 1)

    echo -e "${GREEN}Installation completed successfully!${NC}"
    echo -e "${BLUE}Access the web panel at: http://$SERVER_IP:$WEB_PORT${NC}"
    echo -e "${BLUE}Username: $USERNAME${NC}"
    echo -e "${GREEN}Please save your password securely.${NC}"
}

# Function to uninstall the application
uninstall_application() {
    echo -e "${GREEN}Uninstalling application...${NC}"

    # Stop and disable services
    echo -e "${GREEN}Stopping and disabling services...${NC}"
    sudo systemctl stop 6to4tunnel 2>/dev/null || echo -e "${RED}Failed to stop 6to4tunnel service or service not found${NC}"
    sudo systemctl disable 6to4tunnel 2>/dev/null || echo -e "${RED}Failed to disable 6to4tunnel service or service not found${NC}"
    sudo systemctl stop gost_0.service 2>/dev/null || echo -e "${RED}Failed to stop gost_0 service or service not found${NC}"
    sudo systemctl disable gost_0.service 2>/dev/null || echo -e "${RED}Failed to disable gost_0 service or service not found${NC}"
    sudo systemctl stop sysctl-custom 2>/dev/null || echo -e "${RED}Failed to stop sysctl-custom service or service not found${NC}"
    sudo systemctl disable sysctl-custom 2>/dev/null || echo -e "${RED}Failed to disable sysctl-custom service or service not found${NC}"

    # Remove systemd service files
    echo -e "${GREEN}Removing systemd service files...${NC}"
    sudo rm -f /etc/systemd/system/6to4tunnel.service 2>/dev/null || echo -e "${RED}Failed to remove 6to4tunnel service file${NC}"
    sudo rm -f /usr/lib/systemd/system/gost_0.service 2>/dev/null || echo -e "${RED}Failed to remove gost_0 service file${NC}"
    sudo rm -f /etc/systemd/system/sysctl-custom.service 2>/dev/null || echo -e "${RED}Failed to remove sysctl-custom service file${NC}"
    sudo rm -f /etc/systemd/system/multi-user.target.wants/6to4tunnel.service 2>/dev/null || echo -e "${RED}Failed to remove residual 6to4tunnel systemd files${NC}"
    sudo rm -f /etc/systemd/system/multi-user.target.wants/gost_0.service 2>/dev/null || echo -e "${RED}Failed to remove residual gost_0 systemd files${NC}"
    sudo rm -f /etc/systemd/system/multi-user.target.wants/sysctl-custom.service 2>/dev/null || echo -e "${RED}Failed to remove residual sysctl-custom systemd files${NC}"
    sudo systemctl daemon-reload 2>/dev/null || echo -e "${RED}Failed to reload systemd${NC}"
    sudo systemctl reset-failed 2>/dev/null || echo -e "${RED}Failed to reset failed systemd services${NC}"

    # Remove sudoers file
    echo -e "${GREEN}Removing sudoers file...${NC}"
    sudo rm -f /etc/sudoers.d/6to4tunnel 2>/dev/null || echo -e "${RED}Failed to remove sudoers file${NC}"

    # Remove project directory and all its contents
    echo -e "${GREEN}Removing project directory (/opt/6to4tunnel)...${NC}"
    sudo rm -rf /opt/6to4tunnel 2>/dev/null || echo -e "${RED}Failed to remove project directory${NC}"

    # Remove temporary files and scripts
    echo -e "${GREEN}Removing temporary files and scripts...${NC}"
    sudo rm -f /tmp/gost_* /tmp/gost_update.py 2>/dev/null || echo -e "${RED}Failed to remove temporary files${NC}"
    sudo rm -f /usr/local/bin/move_gost_service.sh 2>/dev/null || echo -e "${RED}Failed to remove move_gost_service.sh${NC}"
    sudo rm -f /usr/bin/auto_restart_cronjob.sh 2>/dev/null || echo -e "${RED}Failed to remove auto_restart_cronjob.sh${NC}"

    # Remove netplan configurations
    echo -e "${GREEN}Removing netplan configurations...${NC}"
    sudo rm -f /etc/netplan/*-netcfg.yaml 2>/dev/null || echo -e "${RED}Failed to remove netplan files${NC}"
    sudo netplan apply 2>/dev/null || echo -e "${RED}Failed to apply netplan${NC}"

    # Remove cron jobs related to auto-restart and cache clearing
    echo -e "${GREEN}Removing cron jobs...${NC}"
    crontab -l 2>/dev/null | grep -v '/usr/bin/auto_restart_cronjob.sh' | crontab - 2>/dev/null || echo -e "${RED}Failed to remove auto-restart cron job${NC}"
    crontab -l 2>/dev/null | grep -v 'drop_caches' | crontab - 2>/dev/null || echo -e "${RED}Failed to remove cache clearing cron job${NC}"

    # Uninstall Node.js and npm
    echo -e "${GREEN}Uninstalling Node.js and npm...${NC}"
    if [ -f /etc/debian_version ]; then
        sudo apt remove -y nodejs npm 2>/dev/null || echo -e "${RED}Failed to remove Node.js and npm${NC}"
        sudo apt autoremove -y 2>/dev/null || echo -e "${RED}Failed to run autoremove${NC}"
    elif [ -f /etc/redhat-release ]; then
        sudo yum remove -y nodejs npm 2>/dev/null || echo -e "${RED}Failed to remove Node.js and npm${NC}"
        sudo yum autoremove -y 2>/dev/null || echo -e "${RED}Failed to run autoremove${NC}"
    fi

    # Uninstall Node.js packages globally
    echo -e "${GREEN}Uninstalling Node.js packages...${NC}"
    sudo npm uninstall -g express bcrypt body-parser express-session ejs 2>/dev/null || echo -e "${RED}Failed to uninstall Node.js packages${NC}"

    # Clean npm cache
    echo -e "${GREEN}Cleaning npm cache...${NC}"
    sudo npm cache clean --force 2>/dev/null || echo -e "${RED}Failed to clean npm cache${NC}"

    # Remove gost binary
    echo -e "${GREEN}Removing gost binary...${NC}"
    sudo rm -f /usr/local/bin/gost 2>/dev/null || echo -e "${RED}Failed to remove gost binary${NC}"

    # Remove residual configuration files
    echo -e "${GREEN}Removing residual configuration files...${NC}"
    sudo rm -rf /etc/gost 2>/dev/null || echo -e "${RED}Failed to remove /etc/gost directory${NC}"

    echo -e "${GREEN}Application uninstalled successfully. You can now reinstall with option 1.${NC}"
}
# Function to view errors
view_errors() {
    echo -e "${GREEN}Displaying recent error logs for 6to4tunnel service...${NC}"
    if sudo systemctl status 6to4tunnel >/dev/null 2>&1; then
        sudo journalctl -u 6to4tunnel -n 50 --no-pager
    else
        echo -e "${RED}Service 6to4tunnel is not running or not installed.${NC}"
    fi
}

# Display menu
clear
echo -e "${BLUE}=======================================${NC}"
echo -e "${GREEN}GostMulti Tunnel Manager Setup${NC}"
echo -e "${BLUE}=======================================${NC}"
echo -e "${GREEN}1) Install Application${NC}"
echo -e "${RED}2) Uninstall Application${NC}"
echo -e "${BLUE}3) View Errors${NC}"
echo -e "${BLUE}----------------------------------------${NC}"
read -p "Enter your choice (1-3): " choice

case $choice in
    1)
        install_application
        ;;
    2)
        uninstall_application
        ;;
    3)
        view_errors
        ;;
    *)
        echo -e "${RED}Invalid option. Please select a number between 1 and 3.${NC}"
        exit 1
        ;;
esac
