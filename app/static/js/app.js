
  // Username ...

  function loadUserDataIntoForm() {
    const _username = localStorage.getItem("username") || ""; // Default to empty string if not found
    const _did = localStorage.getItem("did") || ""; // Default to empty string if not found
  
    // Populate the user in form
    let eltDisplayUsername=document.getElementById("idDisplayUsername");
    if(eltDisplayUsername) {eltDisplayUsername.innerHTML = _username;}
    let eltUsername=document.getElementById("username");
    if(eltUsername) {eltUsername.value = _username;}
    let eltDid=document.getElementById("did");
    if(eltDid) {eltDid.value = _did;}
    let eltDidSender=document.getElementById("did_sender");
    if(eltDidSender) {eltDidSender.value = _did;}
    let eltDisplayDid=document.getElementById("displayDid");
    if(eltDisplayDid) {eltDisplayDid.innerHTML = _did;}
  }
  
  // Save User data to localStorage
  function saveUserDataToLocalStore(objUser) {
    if(objUser.username) {
      localStorage.setItem("username", objUser.username);
    }    
    if(objUser.did) {
      localStorage.setItem("did", objUser.did);
    }
  }
  // secret ...

  function saveSecretKeysToLocalStore() {
    let secret_i=null;
    let secret_sa=null;
    let secret_c=null;
    let secret_pass=null;
    const eltS_i=document.getElementById('secret_i');
    if(eltS_i) {secret_i = eltS_i.value;}
    const eltS_sa=document.getElementById('secret_sa');
    if(eltS_sa) {secret_sa = eltS_sa.value;}
    const eltS_c=document.getElementById('secret_c');
    if(eltS_c) {secret_c = eltS_c.value;}

    let objTS={
      sa: secret_sa,
      i: parseInt(secret_i),
      c: secret_c,
    }

    let userTS = localStorage.getItem("userdata") || "[]";
    userTS=JSON.parse(userTS);
    let i=userTS.findIndex(function (x) {return x.i===secret_i});
    if(i==-1) {
      userTS.push(objTS)
    }
    else {
      userTS[i]=objTS;
    }
    localStorage.setItem("userdata", JSON.stringify(userTS));
  }

  function loadSecretKeysIntoForm(objSecret) {
    if(!objSecret || !objSecret.i || !objSecret.s) {return}

    const eltS_s=document.getElementById('secret_s');
    if(eltS_s && objSecret.s) {eltS_s.value=objSecret.s}
    const eltS_i=document.getElementById('secret_i');
    if(eltS_i && objSecret.i) {eltS_i.value=objSecret.i}
    const eltS_c=document.getElementById('secret_c');
    if(eltS_c && objSecret.c) {eltS_c.value=objSecret.c}

    let userTS = localStorage.getItem("userdata") || "[]";
    userTS=JSON.parse(userTS);
    let i=userTS.findIndex(function (x) {return x.i===objSecret.i});
    if(i!=-1) {
      const eltS_sa=document.getElementById('secret_sa');
      if(eltS_sa && objSecret.sa) {eltS_sa.value=userTS[i].sa}  
    }
  }
  
  // login 

  function onLogin(evt) {
      evt.preventDefault(); // Prevent form submission for demonstration
      const eltUsername=document.getElementById('username');
      const eltDid=document.getElementById('did');
      let _username=null;
      let _did=null;
      if(eltUsername) {
        _username = eltUsername.value;
      }
      if(eltDid) {
        _did = eltDid.value;
      }
      saveUserDataToLocalStore({
        username: _username,
        did: _did
      })

    // Submit the form
      document.getElementById('formLogin').submit();
  } 
  
  function onDecode(evt) {
    evt.preventDefault(); // Prevent form submission for demonstration
    const eltSecret=document.getElementById('secret');
    let objSecret=null;
    if(eltSecret) {
      objSecret=JSON.parse(eltSecret.value);
      loadSecretKeysIntoForm(objSecret)
      
      // Submit the form
      document.getElementById('formDecode').submit();
    }
  }

  // Load form data on page loa
//  window.onload = loadUserDataIntoForm;