const registerBtn = document.getElementById("register-btn");

if (registerBtn) {
  registerBtn.onclick = async function() {
    const username = document.getElementById("reg-username").value.trim();
    const email = document.getElementById("reg-email").value.trim();
    const password = document.getElementById("reg-password").value;
    const confirmPass = document.getElementById("reg-confirm").value;
    const phone = document.getElementById("reg-phone").value.trim();

    if (!username || !password || !email || !phone) {
      alert("Please fill in Username, Email, Phone, and Password!");
      return;
    }

    if (password !== confirmPass) {
      alert("Passwords do not match!");
      return;
    }

    registerBtn.innerText = "Registering...";
    registerBtn.disabled = true;

    try {
      const response = await fetch('https://backend-xpnz.onrender.com/api/auth/register/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          username: username, 
          email: email,
          phone_number: phone,
          password: password 
        })
      });

      const data = await response.json();

      if (response.ok) {
        alert("Account Created Securely! Please login.");
        window.location.href = "index.html";
      } else {
        // Formats Django errors cleanly 
        let errorMsg = "Registration Failed:\\n";
        for (let key in data) { errorMsg += `- ${key}: ${data[key]}\\n`; }
        alert(errorMsg);
        registerBtn.innerText = "Register";
        registerBtn.disabled = false;
      }
    } catch (error) {
      console.error("Networking error:", error);
      alert("Failed to connect to the server. Is Django running?");
      registerBtn.innerText = "Register";
      registerBtn.disabled = false;
    }
  };
}
