// Matrix Rain Effect
class MatrixRain {
    constructor() {
        this.canvas = document.getElementById('matrix-canvas');
        this.ctx = this.canvas.getContext('2d');
        this.characters = '01';
        this.fontSize = 14;
        this.columns = 0;
        this.drops = [];
        
        this.init();
        this.animate();
    }
    
    init() {
        this.resize();
        window.addEventListener('resize', () => this.resize());
    }
    
    resize() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
        this.columns = Math.floor(this.canvas.width / this.fontSize);
        
        // Reset drops array
        this.drops = [];
        for (let i = 0; i < this.columns; i++) {
            this.drops[i] = Math.random() * -100;
        }
    }
    
    draw() {
        // Create fade effect
        this.ctx.fillStyle = 'rgba(11, 11, 11, 0.05)';
        this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);
        
        // Set text properties
        this.ctx.fillStyle = '#00ff66';
        this.ctx.font = `${this.fontSize}px monospace`;
        
        // Draw characters
        for (let i = 0; i < this.drops.length; i++) {
            const char = this.characters[Math.floor(Math.random() * this.characters.length)];
            const x = i * this.fontSize;
            const y = this.drops[i] * this.fontSize;
            
            // Add glow effect
            this.ctx.shadowColor = '#00ff66';
            this.ctx.shadowBlur = 3;
            
            this.ctx.fillText(char, x, y);
            
            // Reset drop if it goes off screen
            if (y > this.canvas.height && Math.random() > 0.975) {
                this.drops[i] = 0;
            }
            
            // Move drop down
            this.drops[i]++;
        }
    }
    
    animate() {
        this.draw();
        requestAnimationFrame(() => this.animate());
    }
}

// Initialize Matrix Rain when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new MatrixRain();
});

// Prevent canvas from interfering with page interactions
document.getElementById('matrix-canvas').addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    return false;
});
