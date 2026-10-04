const API_BASE = window.location.origin;
let selectedStatus = 'Present';
let cameraStream = null;

function setStatus(message, isSuccess = true) {
  const box = document.getElementById('attendance-result');
  box.textContent = message;
  box.style.color = isSuccess ? '#90ee90' : '#ffb3b3';
}

function setFaceStatus(message, isSuccess = true) {
  const box = document.getElementById('face-result');
  box.textContent = message;
  box.style.color = isSuccess ? '#90ee90' : '#ffb3b3';
}

function setCameraStatus(message, isSuccess = true) {
  const box = document.getElementById('camera-status');
  box.textContent = message;
  box.style.color = isSuccess ? '#dfeeff' : '#ffb3b3';
}

function stopCamera() {
  if (cameraStream) {
    cameraStream.getTracks().forEach((track) => track.stop());
    cameraStream = null;
  }

  const video = document.getElementById('camera-feed');
  video.srcObject = null;
  video.hidden = true;
  document.getElementById('camera-placeholder').hidden = false;
  document.getElementById('start-camera-btn').disabled = false;
  document.getElementById('capture-photo-btn').disabled = true;
  document.getElementById('stop-camera-btn').disabled = true;
}

document.getElementById('start-camera-btn').addEventListener('click', async () => {
  if (!navigator.mediaDevices?.getUserMedia) {
    setCameraStatus('Camera access requires a supported browser and a secure connection.', false);
    return;
  }

  const startButton = document.getElementById('start-camera-btn');
  const video = document.getElementById('camera-feed');
  const photo = document.getElementById('captured-photo');
  startButton.disabled = true;
  photo.hidden = true;
  setCameraStatus('Requesting camera access...');

  try {
    cameraStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'user' },
      audio: false,
    });
    video.srcObject = cameraStream;
    video.hidden = false;
    await video.play();
    document.getElementById('camera-placeholder').hidden = true;
    document.getElementById('capture-photo-btn').disabled = false;
    document.getElementById('stop-camera-btn').disabled = false;
    setCameraStatus('Camera is on. Capture a photo when ready.');
  } catch (error) {
    stopCamera();
    const messages = {
      NotAllowedError: 'Camera permission was denied. Allow access in your browser settings.',
      NotFoundError: 'No camera was found on this device.',
      NotReadableError: 'The camera is busy in another application.',
    };
    setCameraStatus(messages[error.name] || 'Unable to start the camera. Check browser permissions and try again.', false);
  }
});

document.getElementById('capture-photo-btn').addEventListener('click', () => {
  const video = document.getElementById('camera-feed');
  if (!video.videoWidth || !video.videoHeight) {
    setCameraStatus('The camera is not ready yet. Try again in a moment.', false);
    return;
  }

  const canvas = document.createElement('canvas');
  canvas.width = video.videoWidth;
  canvas.height = video.videoHeight;
  canvas.getContext('2d').drawImage(video, 0, 0);
  const photo = document.getElementById('captured-photo');
  photo.src = canvas.toDataURL('image/jpeg', 0.9);
  photo.hidden = false;
  setCameraStatus('Photo captured.');
});

document.getElementById('stop-camera-btn').addEventListener('click', () => {
  stopCamera();
  setCameraStatus('Camera stopped.');
});

window.addEventListener('pagehide', stopCamera);

async function apiRequest(endpoint, options = {}) {
  try {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      headers: { 'Content-Type': 'application/json' },
      ...options,
    });

    const data = await response.json().catch(() => ({}));
    return { response, data };
  } catch {
    return {
      response: { ok: false },
      data: { error: 'Cannot reach the backend. Make sure the Flask app is running.' },
    };
  }
}

document.getElementById('student-form').addEventListener('submit', async (event) => {
  event.preventDefault();

  const studentId = document.getElementById('student-id').value.trim();
  const name = document.getElementById('student-name').value.trim();

  if (!studentId || !name) {
    alert('Please enter both student ID and student name.');
    return;
  }

  const { response, data } = await apiRequest('/students', {
    method: 'POST',
    body: JSON.stringify({ student_id: studentId, name }),
  });

  if (response.ok) {
    alert(data.message || 'Student registered successfully');
    document.getElementById('student-form').reset();
  } else {
    alert(data.message || data.error || 'Unable to register student');
  }
});

document.getElementById('face-scan-btn').addEventListener('click', async () => {
  const studentId = document.getElementById('student-id').value.trim();

  if (!studentId) {
    setFaceStatus('Please enter a Student ID first.', false);
    return;
  }

  const { response, data } = await apiRequest('/face-scan', {
    method: 'POST',
    body: JSON.stringify({ student_id: studentId }),
  });

  if (response.ok) {
    setFaceStatus(data.message || 'Face verified successfully', data.success !== false);
    document.getElementById('camera-status').textContent = data.success ? 'Face detected' : 'Verification failed';
  } else {
    setFaceStatus(data.error || 'Face scan failed', false);
  }
});

document.querySelectorAll('.status-btn').forEach((button) => {
  button.addEventListener('click', () => {
    selectedStatus = button.dataset.status;
    document.querySelectorAll('.status-btn').forEach((btn) => btn.classList.remove('active'));
    button.classList.add('active');
    setStatus(`Selected status: ${selectedStatus}`);
  });
});

document.getElementById('mark-attendance-btn').addEventListener('click', async () => {
  const studentId = document.getElementById('student-id').value.trim();

  if (!studentId) {
    setStatus('Please enter a Student ID first.', false);
    return;
  }

  const { response, data } = await apiRequest('/mark-attendance', {
    method: 'POST',
    body: JSON.stringify({ student_id: studentId, status: selectedStatus }),
  });

  if (response.ok) {
    setStatus(data.message || 'Attendance marked successfully', true);
  } else {
    setStatus(data.message || data.error || 'Attendance could not be marked', false);
  }
});

document.getElementById('view-attendance-btn').addEventListener('click', async () => {
  const studentId = document.getElementById('query-student-id').value.trim();

  if (!studentId) {
    document.getElementById('attendance-data').textContent = 'Enter a student ID to view attendance.';
    return;
  }

  const { response, data } = await apiRequest(`/attendance/${encodeURIComponent(studentId)}`);
  if (!response.ok) {
    document.getElementById('attendance-data').textContent = data.error || 'Unable to load attendance.';
    return;
  }

  document.getElementById('attendance-data').textContent = JSON.stringify(data, null, 2);
});

document.getElementById('load-alerts-btn').addEventListener('click', async () => {
  const { response, data } = await apiRequest('/alerts');

  const alertsBox = document.getElementById('alerts-list');
  if (!response.ok) {
    alertsBox.textContent = data.error || 'Unable to load alerts.';
    return;
  }
  if (!data.length) {
    alertsBox.textContent = 'No low attendance alerts.';
    return;
  }

  alertsBox.innerHTML = data.map((item) => `
    <div>
      <strong>${item.name}</strong> (${item.student_id})<br>
      Attendance: ${item.attendance}%<br>
      ${item.alert}
    </div>
  `).join('<hr>');
});

document.addEventListener('DOMContentLoaded', async () => {
  const { response: healthResponse } = await apiRequest('/health');
  if (healthResponse.ok) {
    document.getElementById('backend-status').textContent = 'Backend connected';
  } else {
    document.getElementById('backend-status').textContent = 'Backend unavailable';
    document.getElementById('backend-status').style.color = '#ffb3b3';
  }
});
