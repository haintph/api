// Các phương thức lấy địa chỉ IP
class IPAddressRetriever {
    // Phương thức lấy IP trong môi trường trình duyệt
    static getBrowserIP() {
      return new Promise((resolve, reject) => {
        // Sử dụng WebRTC để lấy IP local
        const pc = new RTCPeerConnection({
          iceServers: []
        });
        
        pc.createDataChannel('');
        
        pc.onicecandidate = (e) => {
          if (!e.candidate) return;
          
          // Regex để trích xuất IPv4
          const ipRegex = /([0-9]{1,3}(\.[0-9]{1,3}){3})/;
          const ipMatch = ipRegex.exec(e.candidate.candidate);
          
          if (ipMatch) {
            const ip = ipMatch[1];
            // Loại bỏ các IP không mong muốn
            if (ip !== '0.0.0.0' && !ip.startsWith('192.168.')) {
              resolve(ip);
              pc.close();
            }
          }
        };
        
        pc.createOffer()
          .then(offer => pc.setLocalDescription(offer))
          .catch(err => reject(err));
      });
    }
  
    // Lấy IP công cộng từ API bên ngoài
    static getPublicIP() {
      return fetch('https://api.ipify.org?format=json')
        .then(response => response.json())
        .then(data => data.ip)
        .catch(() => null);
    }
  
    // Lấy IP từ các header (chỉ hữu ích khi qua proxy/server)
    static getIPFromHeaders(headers) {
      const headerNames = [
        'x-forwarded-for',
        'x-real-ip',
        'cf-connecting-ip',
        'client-ip'
      ];
  
      for (let header of headerNames) {
        const ip = headers[header];
        if (ip) {
          // Lấy IP đầu tiên nếu có nhiều IP
          return ip.split(',')[0].trim();
        }
      }
  
      return null;
    }
  
    // Lấy IP chi tiết cho Windows (sử dụng PowerShell)
    static getWindowsLocalIP() {
      try {
        const { execSync } = require('child_process');
        
        // Lệnh PowerShell lấy địa chỉ IP
        const command = `
          (Get-NetIPConfiguration | 
           Where-Object { $_.IPv4Address.IPAddress -like '192.168.*' }).IPv4Address.IPAddress
        `;
        
        const result = execSync(`powershell -Command "${command}"`, { encoding: 'utf8' });
        return result.trim();
      } catch (error) {
        console.error('Không thể lấy địa chỉ IP:', error);
        return null;
      }
    }
  
    // Lấy IP chi tiết cho MacOS
    static getMacOSLocalIP() {
      try {
        const { execSync } = require('child_process');
        
        // Lệnh lấy IP cho MacOS
        const command = `
          ifconfig | grep -E "inet .*192\\.168\\." | awk '{print $2}'
        `;
        
        const result = execSync(command, { encoding: 'utf8' });
        return result.trim();
      } catch (error) {
        console.error('Không thể lấy địa chỉ IP:', error);
        return null;
      }
    }
  
    // Phương thức tổng hợp để lấy IP
    static async getIPAddress() {
      // Ưu tiên lấy IP local
      if (process.platform === 'win32') {
        const windowsIP = this.getWindowsLocalIP();
        if (windowsIP) return windowsIP;
      } else if (process.platform === 'darwin') {
        const macIP = this.getMacOSLocalIP();
        if (macIP) return macIP;
      }
  
      // Thử lấy IP từ trình duyệt
      try {
        const browserIP = await this.getBrowserIP();
        if (browserIP) return browserIP;
      } catch {}
  
      // Thử lấy IP công cộng
      try {
        const publicIP = await this.getPublicIP();
        if (publicIP) return publicIP;
      } catch {}
  
      return null;
    }
  }
  
  // Sử dụng
  async function demonstrateIPRetrieval() {
    try {
      // Lấy địa chỉ IP
      const ipAddress = await IPAddressRetriever.getIPAddress();
      
      if (ipAddress) {
        console.log('Địa chỉ IP của bạn:', ipAddress);
        
        // Kiểm tra và xác thực định dạng IP
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (ipv4Regex.test(ipAddress)) {
          console.log('Định dạng IP hợp lệ');
        } else {
          console.log('Định dạng IP không hợp lệ');
        }
      } else {
        console.log('Không thể xác định địa chỉ IP');
      }
    } catch (error) {
      console.error('Lỗi khi lấy địa chỉ IP:', error);
    }
  }
  
  // Chạy demo
  demonstrateIPRetrieval();