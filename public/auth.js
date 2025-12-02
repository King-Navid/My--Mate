// Authentication utility for frontend
const Auth = {
  async checkAuth() {
    try {
      const res = await fetch("/api/user", {
        credentials: "include",
      });
      const data = await res.json();
      return data.authenticated ? data.user : null;
    } catch (error) {
      console.error("Auth check error:", error);
      return null;
    }
  },

  async logout() {
    try {
      const res = await fetch("/api/logout", {
        method: "POST",
        credentials: "include",
      });
      const data = await res.json();
      if (res.ok) {
        const isAdminPage = window.location.pathname.includes("admin");
        window.location.href = isAdminPage ? "/admin-login.html" : "/login.html";
      }
      return data;
    } catch (error) {
      console.error("Logout error:", error);
      alert("خطا در خروج از سیستم.");
    }
  },

  async updateNavButtons() {
    const user = await this.checkAuth();
    const navButtons = document.querySelector(".nav-buttons");
    
    if (!navButtons) return;

    // Security: Clear and rebuild using textContent to prevent XSS
    navButtons.innerHTML = '';
    
    if (user) {
      // User is logged in - show logout button
      // Security: Use textContent to prevent XSS
      const supportLink = document.createElement('a');
      supportLink.href = 'chat.html';
      supportLink.className = 'btn-auth';
      supportLink.textContent = 'پشتیبانی';
      navButtons.appendChild(supportLink);

      if (user.isAdmin) {
        const adminLink = document.createElement('a');
        adminLink.href = 'admin.html';
        adminLink.className = 'btn-auth';
        adminLink.textContent = 'پنل مدیریت';
        navButtons.appendChild(adminLink);
      }
      
      const usernameSpan = document.createElement('span');
      usernameSpan.className = 'btn-auth';
      usernameSpan.style.cssText = 'cursor: default; background-color: #4a5568; color: white; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 120px;';
      usernameSpan.textContent = user.username.substring(0, 50);
      navButtons.appendChild(usernameSpan);
      
      const logoutBtn = document.createElement('button');
      logoutBtn.onclick = () => Auth.logout();
      logoutBtn.className = 'btn-auth';
      logoutBtn.style.cssText = 'border: none; font-size: 1.1rem;';
      logoutBtn.textContent = 'خروج';
      navButtons.appendChild(logoutBtn);
    } else {
      // User is not logged in - show login/register buttons
      const supportLink = document.createElement('a');
      supportLink.href = 'chat.html';
      supportLink.className = 'btn-auth';
      supportLink.textContent = 'پشتیبانی';
      navButtons.appendChild(supportLink);
      
      const loginLink = document.createElement('a');
      loginLink.href = 'login.html';
      loginLink.className = 'btn-auth';
      loginLink.textContent = 'ورود';
      navButtons.appendChild(loginLink);
      
      const registerLink = document.createElement('a');
      registerLink.href = 'register.html';
      registerLink.className = 'btn-auth';
      registerLink.textContent = 'ثبت نام';
      navButtons.appendChild(registerLink);
    }
  }
};

