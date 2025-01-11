
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
    let secret_title=null;
    const eltS_i=document.getElementById('secret_i');
    if(eltS_i) {secret_i = eltS_i.value;}
    const eltS_sa=document.getElementById('secret_sa');
    if(eltS_sa) {secret_sa = eltS_sa.value;}
    const eltS_c=document.getElementById('secret_c');
    if(eltS_c) {secret_c = eltS_c.value;}
    const eltS_t=document.getElementById('secret_t');
    if(eltS_t) {secret_title = eltS_t.innerHTML;}
    const eltS_hasVC=document.getElementById('hasVC');
    if(eltS_hasVC) {hasVC = eltS_hasVC.value;}

    let objTS={
      sa: secret_sa,
      i: parseInt(secret_i),
      c: secret_c,
      t: secret_title,
      hasVC: hasVC
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
    const eltS_t=document.getElementById('secret_t');
    if(eltS_t && objSecret.t) {eltS_t.value=objSecret.t}
    const eltS_hasVC=document.getElementById('hasVC');
    if(eltS_hasVC) {eltS_hasVC.value=objSecret.hasVC==true}

    let userTS = localStorage.getItem("userdata") || "[]";
    userTS=JSON.parse(userTS);
    let i=userTS.findIndex(function (x) {return x.i===objSecret.i});
    if(i!=-1) {
      const eltS_sa=document.getElementById('secret_sa');
      if(eltS_sa && objSecret.sa) {eltS_sa.value=userTS[i].sa}  
    }
  }
  
  function getAllSecretsFromSender() {
    let userTS = localStorage.getItem("userdata") || "[]";
    userTS=JSON.parse(userTS);

    if(userTS.length>0) {
      const container = document.getElementById("list-of-secrets");
      container.innerHTML="";

      //  Loop through the array and create HTML elements
      userTS.forEach(item => {
        const itemDiv = document.createElement("div");
        itemDiv.style.marginBottom = "10px";

        const itemTitle = document.createElement("div");
        itemTitle.textContent = (item.t? item.t: "no title") + " "+(item.c? "(does not require a VC to decode)": "(requires a VC to decode)");
        itemTitle.style.display = "inline-flex"; 
        itemTitle.style.marginRight = "10px"; // Add spacing between text and button

        const itemBtn = document.createElement("button");
        itemBtn.textContent = "Select this secret";
        itemBtn.style.display = "inline-flex"; // Add styling (optional)
        itemBtn.style.margin = "5px 10px";

        // Set data-* attributes on the button
        itemBtn.setAttribute("data-i", item.i || "");
        itemBtn.setAttribute("data-c", item.c || "");
        itemBtn.setAttribute("data-t", item.t || "");
        itemBtn.setAttribute("data-vc", item.hasVC || "");


        // Add an onClick listener to populate the form
        const form = document.getElementById("idShare");
        itemBtn.addEventListener("click", (evt) => {
          const eltS_i = document.getElementById("secret_i")
          const eltS_c = document.getElementById("secret_c")
          const eltS_t = document.getElementById("secret_t")
          const eltS_vc = document.getElementById("hasVC")
          const eltS_sel = document.getElementById("selected-item")
           
          // Access the data-* attributes from the clicked button
          const button = evt.target;
          eltS_i.value = button.getAttribute("data-i");
          eltS_c.value = button.getAttribute("data-c");
          eltS_t.value = button.getAttribute("data-t");
          eltS_vc.value = button.getAttribute("data-vc");
          eltS_sel.value = button.getAttribute("data-t");
          form.setAttribute("action", (eltS_vc.value==true || eltS_vc.value=="true")? "/share_with_vc": "/share_no_vc");
        });

        // Append the span and button to the parent div
        itemDiv.appendChild(itemBtn);
        itemDiv.appendChild(itemTitle);

        // Append the parent div to the container
        container.appendChild(itemDiv);
    });
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

      // wipe out previous data if bob
      if(_username=="Bob") {
        localStorage.setItem("userdata", JSON.stringify([]));
      }

    // Submit the form
      document.getElementById('formLogin').submit();
  } 
  
  function onDecode(evt) {
    if(signTransaction(evt, 'formDecode')) {
      const eltSecret=document.getElementById('secret');
      let objSecret=null;
      if(eltSecret) {
        objSecret=JSON.parse(eltSecret.value);
        if(objSecret.c==undefined) {
          objSecret.hasVC=true;
        }
        loadSecretKeysIntoForm(objSecret)
        
        // Submit the form
        document.getElementById('formDecode').submit();
      }
  
    }
  }

  function onAcceptVC(evt, vc) {
      // fill the form before accept as then we go stright to post      
      const eltS_i=document.getElementById('secret_i');
      if(eltS_i) {eltS_i.value=vc.iteration}

      if(signTransaction(evt, 'idAcceptVC')) {

    
        // Submit the form
        document.getElementById('idAcceptVC').submit();        
    }
  }

  // confirm dialog 
  function signTransaction(evt, idForm) {
    evt.preventDefault(); // Prevent form submission for demonstration
    const userConfirmed = confirm("Please sign this transaction to proceed");
    if (userConfirmed) {
      document.getElementById(idForm).submit();
      return true;
    }
    return false;
  }
