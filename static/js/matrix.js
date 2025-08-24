// Circuit Grid Background Effect
class CircuitGrid {
    constructor() {
        this.canvas = document.getElementById('matrix-canvas');
        this.ctx = this.canvas.getContext('2d');
        this.gridSize = 50;
        this.nodes = [];
        this.connections = [];
        this.pulses = [];
        this.animationId = null;
        
        this.init();
        this.generateGrid();
        this.animate();
    }
    
    init() {
        this.resize();
        window.addEventListener('resize', () => {
            this.resize();
            this.generateGrid();
        });
    }
    
    resize() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
    }
    
    generateGrid() {
        this.nodes = [];
        this.connections = [];
        this.pulses = [];
        
        const cols = Math.ceil(this.canvas.width / this.gridSize) + 1;
        const rows = Math.ceil(this.canvas.height / this.gridSize) + 1;
        
        // Create nodes
        for (let x = 0; x < cols; x++) {
            for (let y = 0; y < rows; y++) {
                if (Math.random() > 0.3) { // 70% chance for a node
                    this.nodes.push({
                        x: x * this.gridSize,
                        y: y * this.gridSize,
                        active: Math.random() > 0.8,
                        pulse: 0
                    });
                }
            }
        }
        
        // Create connections between nearby nodes
        this.nodes.forEach((node, index) => {
            this.nodes.forEach((otherNode, otherIndex) => {
                if (index !== otherIndex) {
                    const distance = Math.sqrt(
                        Math.pow(node.x - otherNode.x, 2) + 
                        Math.pow(node.y - otherNode.y, 2)
                    );
                    
                    if (distance <= this.gridSize * 1.5 && Math.random() > 0.6) {
                        this.connections.push({
                            start: node,
                            end: otherNode,
                            active: Math.random() > 0.7
                        });
                    }
                }
            });
        });
    }
    
    drawGrid() {
        // Clear canvas with dark background
        this.ctx.fillStyle = 'rgba(11, 11, 11, 0.95)';
        this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);
        
        // Draw subtle grid lines
        this.ctx.strokeStyle = 'rgba(0, 255, 102, 0.1)';
        this.ctx.lineWidth = 1;
        this.ctx.beginPath();
        
        // Vertical lines
        for (let x = 0; x <= this.canvas.width; x += this.gridSize) {
            this.ctx.moveTo(x, 0);
            this.ctx.lineTo(x, this.canvas.height);
        }
        
        // Horizontal lines
        for (let y = 0; y <= this.canvas.height; y += this.gridSize) {
            this.ctx.moveTo(0, y);
            this.ctx.lineTo(this.canvas.width, y);
        }
        
        this.ctx.stroke();
    }
    
    drawConnections() {
        this.connections.forEach(connection => {
            if (connection.active) {
                this.ctx.strokeStyle = 'rgba(0, 255, 102, 0.3)';
                this.ctx.lineWidth = 1;
                this.ctx.beginPath();
                this.ctx.moveTo(connection.start.x, connection.start.y);
                this.ctx.lineTo(connection.end.x, connection.end.y);
                this.ctx.stroke();
            }
        });
    }
    
    drawNodes() {
        this.nodes.forEach(node => {
            // Draw node circle
            this.ctx.beginPath();
            this.ctx.arc(node.x, node.y, 3, 0, Math.PI * 2);
            
            if (node.active) {
                // Active node with glow
                this.ctx.fillStyle = '#00ff66';
                this.ctx.shadowColor = '#00ff66';
                this.ctx.shadowBlur = 10;
                this.ctx.fill();
                this.ctx.shadowBlur = 0;
                
                // Pulse effect
                node.pulse += 0.1;
                if (node.pulse > Math.PI * 2) node.pulse = 0;
                
                const pulseRadius = 3 + Math.sin(node.pulse) * 2;
                this.ctx.beginPath();
                this.ctx.arc(node.x, node.y, pulseRadius, 0, Math.PI * 2);
                this.ctx.strokeStyle = `rgba(0, 255, 102, ${0.5 - Math.sin(node.pulse) * 0.3})`;
                this.ctx.lineWidth = 1;
                this.ctx.stroke();
            } else {
                // Inactive node
                this.ctx.fillStyle = 'rgba(0, 255, 102, 0.2)';
                this.ctx.fill();
            }
        });
    }
    
    updatePulses() {
        // Add random pulses
        if (Math.random() > 0.98) {
            const activeConnections = this.connections.filter(c => c.active);
            if (activeConnections.length > 0) {
                const connection = activeConnections[Math.floor(Math.random() * activeConnections.length)];
                this.pulses.push({
                    connection: connection,
                    progress: 0,
                    speed: 0.02 + Math.random() * 0.03
                });
            }
        }
        
        // Update and draw pulses
        this.pulses = this.pulses.filter(pulse => {
            pulse.progress += pulse.speed;
            
            if (pulse.progress <= 1) {
                const x = pulse.connection.start.x + 
                    (pulse.connection.end.x - pulse.connection.start.x) * pulse.progress;
                const y = pulse.connection.start.y + 
                    (pulse.connection.end.y - pulse.connection.start.y) * pulse.progress;
                
                // Draw pulse
                this.ctx.beginPath();
                this.ctx.arc(x, y, 4, 0, Math.PI * 2);
                this.ctx.fillStyle = '#00ff66';
                this.ctx.shadowColor = '#00ff66';
                this.ctx.shadowBlur = 15;
                this.ctx.fill();
                this.ctx.shadowBlur = 0;
                
                return true;
            }
            return false;
        });
    }
    
    updateNodes() {
        // Randomly activate/deactivate nodes
        this.nodes.forEach(node => {
            if (Math.random() > 0.999) {
                node.active = !node.active;
            }
        });
        
        // Randomly activate/deactivate connections
        this.connections.forEach(connection => {
            if (Math.random() > 0.995) {
                connection.active = !connection.active;
            }
        });
    }
    
    draw() {
        this.drawGrid();
        this.drawConnections();
        this.drawNodes();
        this.updatePulses();
        this.updateNodes();
    }
    
    animate() {
        this.draw();
        this.animationId = requestAnimationFrame(() => this.animate());
    }
    
    destroy() {
        if (this.animationId) {
            cancelAnimationFrame(this.animationId);
        }
    }
}

// Initialize Circuit Grid when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new CircuitGrid();
});

// Prevent canvas from interfering with page interactions
document.getElementById('matrix-canvas').addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    return false;
});
