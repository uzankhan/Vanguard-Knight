import math
import random
import pygame

# Initialize Pygame
pygame.init()

# Screen dimensions & settings
WIDTH, HEIGHT = 1000, 700
screen = pygame.display.set_mode((WIDTH, HEIGHT))
pygame.display.set_caption("Particle Constellation Network")
clock = pygame.time.Clock()

# Colors
BACKGROUND = (255, 255, 255)      # Pure White Background
PARTICLE_COLOR = (255, 182, 193)  # Light Baby Pink particles
LINE_COLOR = (255, 182, 193)      # Light Baby Pink connecting lines

# Parameters (Lines aur density barhane k liye)
NUM_PARTICLES = 160  # Pehle 120 thay, ab particles barha diye hain
MAX_DISTANCE = 130   # Pehle 110 tha, ab mazeed dhoor se bhi lines connect hongi

class Particle:
    def __init__(self):
        self.x = random.randint(0, WIDTH)
        self.y = random.randint(0, HEIGHT)
        # Random velocity components
        self.vx = random.uniform(-1.5, 1.5)
        self.vy = random.uniform(-1.5, 1.5)
        self.radius = 3.5  # Dots ka size bhi thora sa mota kar diya hai

    def move(self):
        self.x += self.vx
        self.y += self.vy
        # Bounce off screen edges
        if self.x <= 0 or self.x >= WIDTH:
            self.vx *= -1
        if self.y <= 0 or self.y >= HEIGHT:
            self.vy *= -1

    def draw(self, surface):
        pygame.draw.circle(
            surface, PARTICLE_COLOR, (int(self.x), int(self.y)), int(self.radius)
        )

# Create particles
particles = [Particle() for _ in range(NUM_PARTICLES)]

# Transparent lines k liye surface
line_surface = pygame.Surface((WIDTH, HEIGHT), pygame.SRCALPHA)

# Main Loop
running = True
while running:
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            running = False

    # White Background fill karo
    screen.fill(BACKGROUND)
    line_surface.fill((0, 0, 0, 0)) 

    # Update particle positions
    for p in particles:
        p.move()

    # Draw connection lines based on distance
    for i in range(len(particles)):
        for j in range(i + 1, len(particles)):
            p1 = particles[i]
            p2 = particles[j]
            
            dist = math.hypot(p2.x - p1.x, p2.y - p1.y)
            
            if dist < MAX_DISTANCE:
                alpha = int(255 * (1 - (dist / MAX_DISTANCE)))
                color_with_alpha = (*LINE_COLOR, alpha)
                
                # Line thickness ko 1 se barha kar 2 kar diya hai (Mota karne ke liye)
                pygame.draw.line(line_surface, color_with_alpha, (int(p1.x), int(p1.y)), (int(p2.x), int(p2.y)), 2)

    # Lines ko main screen par lao
    screen.blit(line_surface, (0, 0))

    # Particles ko lines k oopar draw karo
    for p in particles:
        p.draw(screen)

    pygame.display.flip()
    clock.tick(60)

pygame.quit()