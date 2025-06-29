const axios = require('axios');
const crypto = require('crypto');

class PiHoleAuthManager {
  constructor(piHoleUrl, adminPassword) {
    this.piHoleUrl = piHoleUrl.replace(/\/$/, '');
    this.adminPassword = adminPassword;
    this.sessionToken = null;
  }

  async authenticate() {
    try {
      const response = await axios.post(`${this.piHoleUrl}/admin/index.php?login`, {
        pw: this.adminPassword
      }, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        withCredentials: true
      });

      if (response.data.includes('loginSuccess')) {
        const cookies = response.headers['set-cookie'];
        this.sessionToken = cookies?.find(cookie => cookie.startsWith('PHPSESSID='));
        return true;
      }
      return false;
    } catch (error) {
      console.error('PiHole authentication failed:', error.message);
      return false;
    }
  }

  async addCustomDNSRule(domain, ip) {
    if (!this.sessionToken) {
      await this.authenticate();
    }

    try {
      const response = await axios.post(`${this.piHoleUrl}/admin/scripts/pi-hole/php/customdns.php`, {
        action: 'add',
        domain: domain,
        ip: ip
      }, {
        headers: {
          'Cookie': this.sessionToken,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      });

      return response.data.success || false;
    } catch (error) {
      console.error('Failed to add custom DNS rule:', error.message);
      return false;
    }
  }

  async blockDomain(domain) {
    if (!this.sessionToken) {
      await this.authenticate();
    }

    try {
      const response = await axios.post(`${this.piHoleUrl}/admin/scripts/pi-hole/php/add.php`, {
        domain: domain,
        list: 'black',
        pw: this.adminPassword
      }, {
        headers: {
          'Cookie': this.sessionToken,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      });

      return response.data.success || false;
    } catch (error) {
      console.error('Failed to block domain:', error.message);
      return false;
    }
  }

  async getQueryTypeOverTime() {
    if (!this.sessionToken) {
      await this.authenticate();
    }

    try {
      const response = await axios.get(`${this.piHoleUrl}/admin/api.php?overTimeDataClients`, {
        headers: {
          'Cookie': this.sessionToken
        }
      });

      return response.data;
    } catch (error) {
      console.error('Failed to get query data:', error.message);
      return null;
    }
  }

  async validateUserAccess(clientIP, userToken) {
    try {
      const response = await axios.post(`${process.env.BACKEND_URL}/api/dns/validate-access`, {
        client_ip: clientIP
      }, {
        headers: {
          'Authorization': `Bearer ${userToken}`
        }
      });

      return response.data.allowed;
    } catch (error) {
      console.error('User validation failed:', error.message);
      return false;
    }
  }
}

const setupPiHoleWithAuth = async () => {
  const piHoleUrl = process.env.PIHOLE_URL || 'http://localhost';
  const adminPassword = process.env.PIHOLE_ADMIN_PASSWORD;
  
  if (!adminPassword) {
    console.error('PIHOLE_ADMIN_PASSWORD environment variable is required');
    process.exit(1);
  }

  const authManager = new PiHoleAuthManager(piHoleUrl, adminPassword);
  
  console.log('Setting up PiHole authentication...');
  
  const authenticated = await authManager.authenticate();
  if (!authenticated) {
    console.error('Failed to authenticate with PiHole');
    process.exit(1);
  }

  console.log('PiHole authentication successful');

  await authManager.addCustomDNSRule('adchute.internal', '127.0.0.1');
  await authManager.addCustomDNSRule('api.adchute.internal', process.env.BACKEND_URL?.replace(/https?:\/\//, '') || 'localhost:3001');

  console.log('PiHole setup completed successfully');
};

if (require.main === module) {
  setupPiHoleWithAuth().catch(console.error);
}

module.exports = PiHoleAuthManager;