const video = document.getElementById('video');
const canvas = document.getElementById('canvas');
const context = canvas.getContext('2d');

// Wait for the DOM to be fully loaded before initializing
document.addEventListener('DOMContentLoaded', () => {
    if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
        navigator.mediaDevices.getUserMedia({
            video: { facingMode: "user" } // Prefer front-facing camera on mobile
        })
        .then(stream => {
            video.srcObject = stream;
            video.play();
        })
        .catch(err => {
            console.error("Camera error:", err);
            Swal.fire("Error", "Cannot access webcam. Please allow camera permission in your browser settings.", "error");
        });
    } else {
        Swal.fire("Unsupported", "Your browser does not support camera access.", "error");
    }
});

// Auto-select room when meeting changes
document.getElementById('meeting').addEventListener('change', function () {
    const selectedOption = this.options[this.selectedIndex];
    const associatedRoomId = selectedOption.getAttribute('data-room');
    if (associatedRoomId) {
        document.getElementById('room').value = associatedRoomId;
    }
});

// Capture attendance
document.getElementById('capture').addEventListener('click', () => {
    const room = document.getElementById('room').value;
    const meeting = document.getElementById('meeting').value;

    if (!room) {
        Swal.fire("Room Required", "Please select a room before marking attendance.", "warning");
        return;
    }

    if (video.videoWidth === 0 || video.videoHeight === 0) {
        Swal.fire("Error", "Camera not ready. Please wait a moment and try again.", "error");
        return;
    }

    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    context.drawImage(video, 0, 0, canvas.width, canvas.height);
    const imageData = canvas.toDataURL('image/jpeg');

    Swal.fire({
        title: 'Checking face…',
        allowOutsideClick: false,
        didOpen: () => Swal.showLoading()
    });

    fetch('/mark_attendance', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ image: imageData, room, meeting })
    })
    .then(response => response.json())
    .then(data => {
        Swal.close();

        // Format embeddings to .3f safely
        const formatEmbedding = arr => Array.isArray(arr) ? arr.map(x => Number(x).toFixed(3)) : [];

        Swal.fire({
            icon: data.status === "success" ? "success" :
                data.status === "failed" ? "error" : "warning",
            title: "Attendance Status",
            html: `
                <p>${data.message}</p>
                <p><strong>Euclidean Distance:</strong> ${data.distance !== undefined ? Number(data.distance).toFixed(3) : 'N/A'}</p>
                <p><strong>Registered Embedding:</strong> [${formatEmbedding(data.registered_embedding?.slice(0, 8)).join(', ')} ...]</p>
                <p><strong>Captured Embedding:</strong> [${formatEmbedding(data.captured_embedding?.slice(0, 8)).join(', ')} ...]</p>
            `
        });
    })
    .catch(err => {
        console.error("Attendance error:", err);
        Swal.close();
        Swal.fire("Error", "An error occurred while marking attendance.", "error");
    });
});
