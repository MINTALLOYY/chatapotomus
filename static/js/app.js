const configNode = document.getElementById("firebase-config");
const firebaseConfig = configNode ? JSON.parse(configNode.textContent) : {};

firebase.initializeApp(firebaseConfig);
const auth = firebase.auth();
const db = firebase.firestore();

const MAX_IMAGE_BYTES = 300 * 1024;
const MAX_IMAGE_EDGE = 1080;

let currentUser = null;
let activeChatId = null;
let chatUnsubscribe = null;

const page = document.body.dataset.page;

const escapeHtml = (text) => {
  if (!text) return "";
  const div = document.createElement('div');
  div.textContent = String(text);
  return div.innerHTML;
};

const setStatus = (element, message) => {
  if (element) {
    element.textContent = message;
  }
};

const apiRequest = async (path, options = {}) => {
  if (!currentUser) {
    throw new Error("Not signed in");
  }
  const token = await currentUser.getIdToken();
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      ...(options.headers || {}),
    },
  });

  if (!response.ok) {
    const payload = await response.json();
    throw new Error(payload.error || "Request failed");
  }
  return response.json();
};

const syncSession = async (user) => {
  if (!user) {
    await fetch("/api/session", { method: "DELETE" });
    return;
  }
  const token = await user.getIdToken();
  await fetch("/api/session", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
};

const ensureBootstrap = async () => {
  const token = await currentUser.getIdToken();
  await fetch("/api/users/bootstrap", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
};

const compressImage = (file) =>
  new Promise((resolve, reject) => {
    const image = new Image();
    const reader = new FileReader();
    reader.onload = () => {
      image.src = reader.result;
    };
    reader.onerror = () => reject(new Error("Failed to read image"));
    reader.readAsDataURL(file);

    image.onload = () => {
      const scale = Math.min(
        1,
        MAX_IMAGE_EDGE / Math.max(image.width, image.height)
      );
      const canvas = document.createElement("canvas");
      canvas.width = Math.round(image.width * scale);
      canvas.height = Math.round(image.height * scale);
      const ctx = canvas.getContext("2d");
      ctx.drawImage(image, 0, 0, canvas.width, canvas.height);

      let quality = 0.9;
      const attempt = () => {
        canvas.toBlob(
          (blob) => {
            if (!blob) {
              reject(new Error("Compression failed"));
              return;
            }
            if (blob.size <= MAX_IMAGE_BYTES || quality <= 0.5) {
              resolve(blob);
            } else {
              quality -= 0.1;
              attempt();
            }
          },
          "image/jpeg",
          quality
        );
      };
      attempt();
    };
  });

const initLogin = () => {
  const emailInput = document.getElementById("email");
  const passwordInput = document.getElementById("password");
  const loginBtn = document.getElementById("loginBtn");
  const toggleCreateBtn = document.getElementById("toggleCreateBtn");
  const sendVerifyBtn = document.getElementById("sendVerifyBtn");
  const refreshVerifyBtn = document.getElementById("refreshVerifyBtn");
  const verifyNotice = document.getElementById("verifyNotice");
  const usernameBlock = document.getElementById("usernameBlock");
  const saveUsernameBtn = document.getElementById("saveUsernameBtn");
  const usernameInput = document.getElementById("username");
  const authStatus = document.getElementById("authStatus");

  let createMode = false;

  const setCreateMode = (enabled) => {
    createMode = enabled;
    toggleCreateBtn.textContent = enabled ? "Log in instead" : "Create account";
    loginBtn.textContent = enabled ? "Create account" : "Log in";
  };

  toggleCreateBtn.addEventListener("click", () => {
    setCreateMode(!createMode);
  });

  loginBtn.addEventListener("click", async () => {
    const email = emailInput.value.trim();
    const password = passwordInput.value.trim();
    if (!email || !password) {
      setStatus(authStatus, "Email and password required");
      return;
    }
    try {
      if (createMode) {
        await auth.createUserWithEmailAndPassword(email, password);
        if (auth.currentUser) {
          await auth.currentUser.sendEmailVerification();
        }
        setStatus(authStatus, "Account created. Check email to verify.");
      } else {
        await auth.signInWithEmailAndPassword(email, password);
      }
    } catch (error) {
      setStatus(authStatus, error.message);
    }
  });

  sendVerifyBtn.addEventListener("click", async () => {
    if (!auth.currentUser) return;
    try {
      await auth.currentUser.sendEmailVerification();
      setStatus(authStatus, "Verification email sent.");
    } catch (error) {
      setStatus(authStatus, error.message);
    }
  });

  refreshVerifyBtn.addEventListener("click", async () => {
    if (!auth.currentUser) return;
    await auth.currentUser.reload();
    if (auth.currentUser.emailVerified) {
      // Force token refresh to update the email_verified claim in the JWT
      await auth.currentUser.getIdToken(true);
      await syncSession(auth.currentUser);
      await ensureBootstrap();
      await handleVerifiedLogin();
    } else {
      setStatus(authStatus, "Email still unverified.");
    }
  });

  const handleVerifiedLogin = async () => {
    const me = await apiRequest("/api/users/me");
    if (!me.username) {
      usernameBlock.dataset.hidden = "false";
      saveUsernameBtn.disabled = false;
      setStatus(authStatus, "Pick a username to continue.");
      return;
    }
    window.location.href = "/home";
  };

  saveUsernameBtn.addEventListener("click", async () => {
    const username = usernameInput.value.trim();
    if (!username) {
      setStatus(authStatus, "Username required.");
      return;
    }
    try {
      await apiRequest("/api/users", {
        method: "POST",
        body: JSON.stringify({ username }),
      });
      window.location.href = "/home";
    } catch (error) {
      setStatus(authStatus, error.message);
    }
  });

  const updateVerifyState = (user) => {
    if (!user) return;
    sendVerifyBtn.disabled = false;
    refreshVerifyBtn.disabled = false;
    if (!user.emailVerified) {
      verifyNotice.dataset.visible = "true";
    }
  };

  auth.onAuthStateChanged(async (user) => {
    currentUser = user;
    if (!user) return;
    if (!user.emailVerified) {
      updateVerifyState(user);
      return;
    }
    await syncSession(user);
    await ensureBootstrap();
    await handleVerifiedLogin();
  });
};

const initHome = async () => {
  const signOutBtn = document.getElementById("signOutBtn");
  const addStoryLink = document.getElementById("addStoryLink");
  const storyRow = document.getElementById("storyRow");
  const storyRowStatus = document.getElementById("storyRowStatus");
  const friendList = document.getElementById("friendList");
  const friendsStatus = document.getElementById("friendsStatus");
  const storyViewer = document.getElementById("storyViewer");
  const storyImage = document.getElementById("storyImage");
  const storyHeader = document.getElementById("storyHeader");
  const closeStoryBtn = document.getElementById("closeStoryBtn");

  signOutBtn.addEventListener("click", async () => {
    await auth.signOut();
    await syncSession(null);
    window.location.href = "/login";
  });

  const me = await apiRequest("/api/users/me");
  if (me.storyPosted) {
    addStoryLink.classList.add("disabled");
    addStoryLink.setAttribute("aria-disabled", "true");
  }

  const storiesResponse = await apiRequest("/api/stories");
  storyRow.innerHTML = "";
  if (!storiesResponse.stories.length) {
    storyRowStatus.textContent = "No active stories.";
  }
  storiesResponse.stories.forEach((story) => {
    const card = document.createElement("button");
    card.className = "story-tile";
    card.innerHTML = `<span class="story-avatar"></span><span class="story-name">${story.ownerUsername}</span>`;
    card.addEventListener("click", () => viewStory(story));
    storyRow.appendChild(card);
  });

  const friendsResponse = await apiRequest("/api/users/friends");
  friendList.innerHTML = "";
  if (!friendsResponse.friends.length) {
    friendsStatus.textContent = "No friends yet.";
  }
  friendsResponse.friends.forEach((friend) => {
    const item = document.createElement("div");
    item.className = "friend-card";
    item.innerHTML = `
      <div class="friend-meta">
        <div class="avatar"></div>
        <div>
          <p class="friend-name">${friend.username}</p>
        </div>
      </div>
      <a class="btn subtle" href="/messages/${friend.uid}">Message</a>
    `;
    friendList.appendChild(item);
  });

  const viewStory = async (story) => {
    try {
      const response = await apiRequest(
        `/api/stories/${story.storyId}/media/${story.mediaId}/view`,
        { method: "POST" }
      );
      storyImage.src = response.viewUrl;
      storyHeader.textContent = story.ownerUsername;
      storyViewer.showModal();
    } catch (error) {
      storyRowStatus.textContent = error.message;
    }
  };

  closeStoryBtn.addEventListener("click", () => storyViewer.close());
  storyViewer.addEventListener("click", (event) => {
    if (event.target === storyViewer) {
      storyViewer.close();
    }
  });
};

const initAddStory = async () => {
  const signOutBtn = document.getElementById("signOutBtn");
  const storyFile = document.getElementById("storyFile");
  const storyPreview = document.getElementById("storyPreview");
  const uploadStoryBtn = document.getElementById("uploadStoryBtn");
  const storyStatus = document.getElementById("storyStatus");
  let compressedBlob = null;

  signOutBtn.addEventListener("click", async () => {
    await auth.signOut();
    await syncSession(null);
    window.location.href = "/login";
  });

  const me = await apiRequest("/api/users/me");
  if (me.storyPosted) {
    storyStatus.textContent = "Story already posted for today.";
    uploadStoryBtn.disabled = true;
    storyFile.disabled = true;
    return;
  }

  storyFile.addEventListener("change", async () => {
    const file = storyFile.files[0];
    if (!file) return;
    storyStatus.textContent = "";
    storyPreview.innerHTML = "<span class=\"muted\">Processing...</span>";
    try {
      compressedBlob = await compressImage(file);
      if (compressedBlob.size > MAX_IMAGE_BYTES) {
        storyStatus.textContent = "Image still too large after compression.";
        uploadStoryBtn.disabled = true;
        return;
      }
      const previewUrl = URL.createObjectURL(compressedBlob);
      storyPreview.innerHTML = `<img src="${previewUrl}" alt="Preview" />`;
      uploadStoryBtn.disabled = false;
    } catch (error) {
      storyStatus.textContent = error.message;
      uploadStoryBtn.disabled = true;
    }
  });

  uploadStoryBtn.addEventListener("click", async () => {
    if (!compressedBlob) return;
    setStatus(storyStatus, "Uploading...");
    try {
      // Ask backend for a story and storage path
      const { storyId, mediaId, storagePath, expiresAt } = await apiRequest("/api/stories", {
        method: "POST",
        body: JSON.stringify({ contentType: compressedBlob.type }),
      });

      // Upload via Firebase Web Storage SDK (compat build is already loaded)
      const storage = firebase.storage();
      const storageRef = storage.ref(storagePath);
      await storageRef.put(compressedBlob, { contentType: compressedBlob.type });

      setStatus(storyStatus, "Uploaded. Redirecting...");
      window.location.href = "/home";
    } catch (error) {
      setStatus(storyStatus, error.message || "Upload failed");
      console.error(error);
    }
  });
};

const initMessagesHome = async () => {
  const signOutBtn = document.getElementById("signOutBtn");
  const recentList = document.getElementById("recentList");
  const friendsList = document.getElementById("friendsList");
  const requestsList = document.getElementById("requestsList");
  const recentStatus = document.getElementById("recentStatus");

  signOutBtn.addEventListener("click", async () => {
    await auth.signOut();
    await syncSession(null);
    window.location.href = "/login";
  });

  const [chats, friends, requests] = await Promise.all([
    apiRequest("/api/chats"),
    apiRequest("/api/users/friends"),
    apiRequest("/api/connections/requests"),
  ]);

  const friendMap = new Map(
    friends.friends.map((friend) => [friend.uid, friend.username])
  );

  const messaged = new Set();
  recentList.innerHTML = "";
  if (!chats.chats.length) {
    recentStatus.textContent = "No recent chats yet.";
  }
  chats.chats.forEach((chat) => {
    const partnerUid = chat.participants.find((uid) => uid !== currentUser.uid);
    if (!partnerUid) return;
    messaged.add(partnerUid);
    const item = document.createElement("a");
    item.className = "list-item";
    item.href = `/messages/${partnerUid}`;
    item.innerHTML = `
      <span>${friendMap.get(partnerUid) || "Unknown"}</span>
      <span class="muted">Open</span>
    `;
    recentList.appendChild(item);
  });

  // Display connection requests
  requestsList.innerHTML = "";
  if (!requests.requests.length) {
    requestsList.innerHTML = '<p class="muted" style="padding: 1rem;">No pending requests</p>';
  } else {
    requests.requests.forEach((request) => {
      const item = document.createElement("a");
      item.className = "list-item";
      item.href = `/messages/${request.requesterUid}`;
      item.innerHTML = `
        <span>${escapeHtml(request.requesterUsername)}</span>
        <span class="muted">New request</span>
      `;
      requestsList.appendChild(item);
    });
  }

  friendsList.innerHTML = "";
  // For each friend, check connection status
  // Note: This makes individual API calls per friend (N+1 query pattern).
  // For production with many users, consider implementing a batch endpoint like
  // POST /api/connections/status/batch with body: {"userIds": ["uid1", "uid2", ...]}
  for (const friend of friends.friends) {
    if (messaged.has(friend.uid)) continue;
    
    try {
      const statusData = await apiRequest(`/api/connections/status/${friend.uid}`);
      const item = document.createElement("div");
      item.className = "list-item";
      item.style.cursor = "default";
      
      if (statusData.status === "self") {
        // Skip self - shouldn't message yourself
        continue;
      } else if (statusData.status === "accepted") {
        // Can message - create link
        const link = document.createElement("a");
        link.href = `/messages/${friend.uid}`;
        link.className = "list-item";
        link.innerHTML = `
          <span>${escapeHtml(friend.username)}</span>
          <span class="muted">Message</span>
        `;
        friendsList.appendChild(link);
      } else if (statusData.status === "pending_sent") {
        // Already sent invite
        item.innerHTML = `
          <span>${escapeHtml(friend.username)}</span>
          <span class="muted">Requested</span>
        `;
        friendsList.appendChild(item);
      } else if (statusData.status === "pending_received") {
        // They sent us an invite - show in requests instead
        continue;
      } else if (statusData.status === "blocked") {
        // User is blocked - don't show them
        continue;
      } else if (statusData.status === "none") {
        // Show invite button
        item.innerHTML = `
          <span>${escapeHtml(friend.username)}</span>
          <button class="btn subtle" data-uid="${friend.uid}" data-username="${escapeHtml(friend.username)}">Invite</button>
        `;
        friendsList.appendChild(item);
        
        // Add click handler for invite button
        const inviteBtn = item.querySelector("button");
        inviteBtn.addEventListener("click", async (e) => {
          e.preventDefault();
          const uid = inviteBtn.dataset.uid;
          const username = inviteBtn.dataset.username;
          const message = prompt(`Send an invite to ${username}:\n\nOptional personal message:`);
          if (message === null) return; // User cancelled
          
          try {
            await apiRequest("/api/connections/invite", {
              method: "POST",
              body: JSON.stringify({
                recipientUid: uid,
                inviteMessage: message,
              }),
            });
            inviteBtn.textContent = "Requested";
            inviteBtn.disabled = true;
            inviteBtn.className = "btn ghost";
          } catch (error) {
            alert("Failed to send invite: " + error.message);
          }
        });
      }
    } catch (error) {
      console.error(`Failed to check status for ${friend.uid}:`, error);
      // Default to showing invite button on error
      const item = document.createElement("div");
      item.className = "list-item";
      item.innerHTML = `
        <span>${escapeHtml(friend.username)}</span>
        <span class="muted">Error</span>
      `;
      friendsList.appendChild(item);
    }
  }
};

const initMessageThread = async () => {
  const signOutBtn = document.getElementById("signOutBtn");
  const conversationList = document.getElementById("conversationList");
  const chatWindow = document.getElementById("chatWindow");
  const chatMessageInput = document.getElementById("chatMessage");
  const sendMessageBtn = document.getElementById("sendMessageBtn");
  const chatStatus = document.getElementById("chatStatus");
  const partnerUid = document.body.dataset.partnerUid;

  signOutBtn.addEventListener("click", async () => {
    await auth.signOut();
    await syncSession(null);
    window.location.href = "/login";
  });

  // Check connection status first
  let connectionStatus;
  try {
    connectionStatus = await apiRequest(`/api/connections/status/${partnerUid}`);
  } catch (error) {
    setStatus(chatStatus, "Failed to check connection status: " + error.message);
    return;
  }

  // Handle self case
  if (connectionStatus.status === "self") {
    chatWindow.innerHTML = `
      <div class="invite-card">
        <div class="invite-header">
          You cannot message yourself
        </div>
        <p class="muted">Please select another user to message.</p>
      </div>
    `;
    chatMessageInput.disabled = true;
    sendMessageBtn.disabled = true;
    return;
  }

  // Handle pending connections
  if (connectionStatus.status === "pending_received") {
    // Show invitation card
    const partnerProfile = await apiRequest("/api/users/friends").then(data => 
      data.friends.find(f => f.uid === partnerUid)
    );
    const partnerName = partnerProfile?.username || "Unknown";
    
    chatWindow.innerHTML = `
      <div class="invite-card">
        <div class="invite-header">
          <strong>${escapeHtml(partnerName)}</strong> wants to connect!
        </div>
        ${connectionStatus.inviteMessage ? `<div class="invite-message">"${escapeHtml(connectionStatus.inviteMessage)}"</div>` : ''}
        <div class="invite-actions">
          <button id="acceptBtn" class="btn">Accept</button>
          <button id="ignoreBtn" class="btn ghost">Ignore</button>
          <button id="blockBtn" class="btn ghost">Block &amp; Report</button>
        </div>
      </div>
    `;
    
    document.getElementById("acceptBtn").addEventListener("click", async () => {
      try {
        await apiRequest(`/api/connections/${connectionStatus.connectionId}/accept`, {
          method: "POST",
        });
        location.reload();
      } catch (error) {
        setStatus(chatStatus, "Failed to accept: " + error.message);
      }
    });
    
    document.getElementById("ignoreBtn").addEventListener("click", async () => {
      try {
        await apiRequest(`/api/connections/${connectionStatus.connectionId}/decline`, {
          method: "POST",
        });
        window.location.href = "/messages";
      } catch (error) {
        setStatus(chatStatus, "Failed to decline: " + error.message);
      }
    });
    
    document.getElementById("blockBtn").addEventListener("click", async () => {
      if (!confirm("Block this user and report them?")) return;
      try {
        await apiRequest(`/api/connections/${connectionStatus.connectionId}/block`, {
          method: "POST",
        });
        window.location.href = "/messages";
      } catch (error) {
        setStatus(chatStatus, "Failed to block: " + error.message);
      }
    });
    
    chatMessageInput.disabled = true;
    sendMessageBtn.disabled = true;
    return;
  } else if (connectionStatus.status === "pending_sent") {
    chatWindow.innerHTML = `
      <div class="invite-card">
        <div class="invite-header">
          Connection request pending
        </div>
        <p class="muted">Waiting for the other person to accept your invite.</p>
      </div>
    `;
    chatMessageInput.disabled = true;
    sendMessageBtn.disabled = true;
    return;
  } else if (connectionStatus.status === "none") {
    // No connection - show invite option
    const partnerProfile = await apiRequest("/api/users/friends").then(data => 
      data.friends.find(f => f.uid === partnerUid)
    );
    const partnerName = partnerProfile?.username || "Unknown";
    
    chatWindow.innerHTML = `
      <div class="invite-card">
        <div class="invite-header">
          Send an invite to ${escapeHtml(partnerName)}
        </div>
        <textarea id="inviteMessageText" placeholder="Optional personal message..." style="width: 100%; min-height: 80px; margin: 1rem 0; padding: 0.5rem;"></textarea>
        <button id="sendInviteBtn" class="btn">Send Invite</button>
      </div>
    `;
    
    document.getElementById("sendInviteBtn").addEventListener("click", async () => {
      const message = document.getElementById("inviteMessageText").value;
      try {
        await apiRequest("/api/connections/invite", {
          method: "POST",
          body: JSON.stringify({
            recipientUid: partnerUid,
            inviteMessage: message,
          }),
        });
        location.reload();
      } catch (error) {
        setStatus(chatStatus, "Failed to send invite: " + error.message);
      }
    });
    
    chatMessageInput.disabled = true;
    sendMessageBtn.disabled = true;
    return;
  } else if (connectionStatus.status === "blocked") {
    chatWindow.innerHTML = `
      <div class="invite-card">
        <div class="invite-header">
          Unable to message this user
        </div>
        <p class="muted">This conversation is not available.</p>
      </div>
    `;
    chatMessageInput.disabled = true;
    sendMessageBtn.disabled = true;
    return;
  }

  // Connection is accepted - proceed with normal chat
  let chatData;
  try {
    chatData = await apiRequest("/api/chats", {
      method: "POST",
      body: JSON.stringify({ participantUid: partnerUid }),
    });
    activeChatId = chatData.chatId;
    sendMessageBtn.disabled = false;
  } catch (error) {
    setStatus(chatStatus, "Failed to create chat: " + error.message);
    chatMessageInput.disabled = true;
    sendMessageBtn.disabled = true;
    return;
  }

  let friendMap = new Map();
  try {
    const [chats, friends, me] = await Promise.all([
      apiRequest("/api/chats"),
      apiRequest("/api/users/friends"),
      apiRequest("/api/users/me"),
    ]);
    friendMap = new Map(
      friends.friends.map((friend) => [friend.uid, friend.username])
    );
    // Add current user to the map
    friendMap.set(currentUser.uid, me.username);

    conversationList.innerHTML = "";
    chats.chats.forEach((chat) => {
      const partner = chat.participants.find((uid) => uid !== currentUser.uid);
      const link = document.createElement("a");
      link.className = "list-item";
      if (partner === partnerUid) {
        link.classList.add("active");
      }
      link.href = `/messages/${partner}`;
      link.innerHTML = `<span>${escapeHtml(friendMap.get(partner) || "Unknown")}</span>`;
      conversationList.appendChild(link);
    });
  } catch (error) {
    setStatus(chatStatus, "Failed to load conversations: " + error.message);
    // Continue with empty friendMap - messages will show "Unknown" as sender
  }

  const formatTimestamp = (timestamp) => {
    if (!timestamp) return "";
    try {
      // Handle Firestore Timestamp objects
      const date = timestamp.toDate ? timestamp.toDate() : new Date(timestamp);
      if (isNaN(date.getTime())) return "";
      const now = new Date();
      const isToday = date.toDateString() === now.toDateString();
      const timeStr = date.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true });
      return isToday ? timeStr : `${date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })} ${timeStr}`;
    } catch (error) {
      return "";
    }
  };

  const listenToChat = () => {
    if (chatUnsubscribe) chatUnsubscribe();
    chatUnsubscribe = db
      .collection("messages")
      .where("chatId", "==", activeChatId)
      .orderBy("createdAt")
      .limit(100)
      .onSnapshot((snapshot) => {
        chatWindow.innerHTML = "";
        snapshot.docs.forEach((doc) => {
          const message = doc.data();
          const bubble = document.createElement("div");
          bubble.className = "chat-message";
          const isMine = message.senderUid === currentUser.uid;
          if (isMine) {
            bubble.classList.add("mine");
          }
          
          const senderName = friendMap.get(message.senderUid) || "Unknown";
          const timestamp = formatTimestamp(message.createdAt);
          
          bubble.innerHTML = `
            <div class="message-header">
              <span class="message-sender">${escapeHtml(senderName)}</span>
              <span class="message-time">${timestamp}</span>
            </div>
            <div class="message-text">${escapeHtml(message.contentRef)}</div>
          `;
          chatWindow.appendChild(bubble);
        });
        chatWindow.scrollTop = chatWindow.scrollHeight;
      });
  };

  listenToChat();

  const sendMessage = async () => {
    const text = chatMessageInput.value.trim();
    if (!text) return;
    try {
      await apiRequest(`/api/chats/${activeChatId}/messages`, {
        method: "POST",
        body: JSON.stringify({ type: "text", text }),
      });
      chatMessageInput.value = "";
    } catch (error) {
      setStatus(chatStatus, error.message);
    }
  };

  sendMessageBtn.addEventListener("click", sendMessage);
  chatMessageInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      sendMessage();
    }
  });
};

auth.onAuthStateChanged(async (user) => {
  currentUser = user;
  if (!user) {
    if (page !== "login") {
      window.location.href = "/login";
    }
    return;
  }

  if (!user.emailVerified) {
    await syncSession(user);
    if (page !== "login") {
      window.location.href = "/login?verify=true";
    }
    return;
  }

  await syncSession(user);
  await ensureBootstrap();

  if (page === "login") {
    const me = await apiRequest("/api/users/me");
    if (me.username) {
      window.location.href = "/home";
    }
    return;
  }

  if (page === "home") {
    await initHome();
  } else if (page === "add-story") {
    await initAddStory();
  } else if (page === "messages") {
    await initMessagesHome();
  } else if (page === "message-thread") {
    await initMessageThread();
  }
});

if (page === "login") {
  initLogin();
}
