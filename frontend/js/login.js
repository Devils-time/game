const loginBtn = document.querySelector(".login-btn");
const registerBtn = document.querySelector(".register-btn");

loginBtn.onclick = async function() {
  const userEl = document.getElementById("username");
  const passEl = document.getElementById("password");
  
  const username = userEl.value.trim();
  const password = passEl.value.trim();
  
  if (!username || !password) {
    alert("Please enter both Username and Password.");
    return;
  }
  
  loginBtn.innerText = "Logging in...";
  loginBtn.disabled = true;

  try {
    const response = await fetch('http://127.0.0.1:8000/api/auth/login/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    
    const data = await response.json();
    
    if (response.ok) {
      // Securely store the JWT token for future backend requests
      localStorage.setItem('access_token', data.access);
      localStorage.setItem('refresh_token', data.refresh);
      window.location.href = "dashboard.html";
    } else {
      alert("Login Failed: " + (data.detail || "Invalid credentials"));
      loginBtn.innerText = "Login";
      loginBtn.disabled = false;
    }
  } catch (error) {
    console.error("Networking error:", error);
    alert("Failed to connect to the server. Is Django running?");
    loginBtn.innerText = "Login";
    loginBtn.disabled = false;
  }
};

registerBtn.onclick = function() {
  window.location.href = "register.html";
};

function togglePassword() {
  let passwordField = document.getElementById("password");
  if(passwordField.type === "password") {
    passwordField.type = "text";
  } else {
    passwordField.type = "password";
  }
}