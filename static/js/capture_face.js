$(document).ready(function() {
    // Get access to the webcam
    navigator.mediaDevices.getUserMedia({ video: true })
        .then(function(stream) {
            var video = document.getElementById('video');
            video.srcObject = stream;
            video.play();
        })
        .catch(function(err) {
            console.log("An error occurred: " + err);
        });

    // Get video and overlay canvas elements
    var video = document.getElementById('video');
    var canvas = document.getElementById('overlay');
    var context = canvas.getContext('2d');

    // When video metadata is loaded, set canvas size to match the video
    video.addEventListener('loadedmetadata', function() {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
    });

    // Draw face detection box on the overlay canvas
    function drawFaceBox(face) {
        context.clearRect(0, 0, canvas.width, canvas.height);
        context.beginPath();
        context.lineWidth = '2';
        context.strokeStyle = 'red';
        context.rect(face.left, face.top, face.width, face.height);
        context.stroke();
    }

    // Continuously detect faces and draw face boxes
    video.addEventListener('play', function() {
        var timer = setInterval(function() {
            // Detect faces in the video frame
            var faceDetector = new window.FaceDetector();
            faceDetector.detect(video)
                .then(function(faces) {
                    if (faces.length > 0) {
                        // Draw face box for the first detected face
                        drawFaceBox(faces[0].boundingBox);
                    } else {
                        // Clear overlay canvas if no face detected
                        context.clearRect(0, 0, canvas.width, canvas.height);
                    }
                })
                .catch(function(err) {
                    console.log("Face detection error: " + err);
                });
        }, 100); // Adjust interval as needed
    });

    // Capture and save facial data
    $('#capture-btn').click(function() {
        // Capture facial data
        var facialData = canvas.toDataURL('image/jpeg');

        // Send facial data to the server
        $.ajax({
            type: 'POST',
            url: '/capture_face/{{ user.id }}', // Update this URL to match your route
            data: {
                facial_data: facialData
            },
            success: function(response) {
                alert('Facial data saved successfully!');
            },
            error: function(xhr, status, error) {
                alert('Error saving facial data: ' + error);
            }
        });
    });
});
