const totalSeconds = 180;
let currentSeconds = totalSeconds;

const bar = document.querySelector('.progress-bar');
const timerText = document.getElementById('timer-text');

const interval = setInterval(() => {
currentSeconds--;

const minutes = Math.floor(currentSeconds / 60);
const seconds = currentSeconds % 60;
timerText.textContent = `Kod wygaśnie za: ${minutes} min ${seconds} sek.`;

const widthPercent = (currentSeconds / totalSeconds) * 100;
bar.style.width = `${widthPercent}%`;

if (currentSeconds <= 0) {
  clearInterval(interval);
  timerText.textContent = "Kod wygasł.";
  bar.style.width = "0%";
}
}, 1000);

function generateRandomCode(length = 6) {
return Math.floor(100000 + Math.random() * 900000).toString();
}

function updateQRCode() {
const code = generateRandomCode();
const qrImage = document.getElementById('qr-image');
const codeText = document.getElementById('qr-code-text');

qrImage.src = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${code}`;
codeText.textContent = code;
}

updateQRCode();
