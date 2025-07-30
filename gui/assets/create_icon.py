#!/usr/bin/env python3
"""
Create NetSecureX application icon
"""

from PIL import Image, ImageDraw, ImageFont
import os

def create_netsecurex_icon():
    """Create a professional NetSecureX icon."""
    
    # Icon size
    size = 512
    
    # Create image with transparent background
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Colors
    bg_color = (0, 0, 0, 255)  # Black background
    primary_color = (0, 255, 0, 255)  # Bright green
    secondary_color = (0, 128, 0, 255)  # Dark green
    accent_color = (255, 255, 0, 255)  # Yellow
    
    # Draw background circle
    margin = 20
    draw.ellipse([margin, margin, size-margin, size-margin], 
                fill=bg_color, outline=primary_color, width=8)
    
    # Draw shield shape (security symbol)
    shield_width = size // 3
    shield_height = shield_width * 1.2
    shield_x = (size - shield_width) // 2
    shield_y = (size - shield_height) // 2 - 20
    
    # Shield outline
    shield_points = [
        (shield_x + shield_width//2, shield_y),  # Top center
        (shield_x + shield_width, shield_y + shield_height//3),  # Top right
        (shield_x + shield_width, shield_y + shield_height*2//3),  # Bottom right
        (shield_x + shield_width//2, shield_y + shield_height),  # Bottom center
        (shield_x, shield_y + shield_height*2//3),  # Bottom left
        (shield_x, shield_y + shield_height//3),  # Top left
    ]
    
    draw.polygon(shield_points, fill=secondary_color, outline=primary_color, width=4)
    
    # Draw "N" in the shield
    font_size = shield_width // 3
    try:
        # Try to use a monospace font
        font = ImageFont.truetype("/System/Library/Fonts/Courier.ttc", font_size)
    except:
        try:
            font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", font_size)
        except:
            font = ImageFont.load_default()
    
    # Draw "N" for NetSecureX
    text = "N"
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    text_x = shield_x + (shield_width - text_width) // 2
    text_y = shield_y + (shield_height - text_height) // 2 - 10
    
    draw.text((text_x, text_y), text, fill=accent_color, font=font)
    
    # Draw network nodes around the shield
    node_radius = 8
    nodes = [
        (size//4, size//4),
        (3*size//4, size//4),
        (size//6, size//2),
        (5*size//6, size//2),
        (size//4, 3*size//4),
        (3*size//4, 3*size//4),
    ]
    
    for node_x, node_y in nodes:
        draw.ellipse([node_x-node_radius, node_y-node_radius, 
                     node_x+node_radius, node_y+node_radius], 
                    fill=primary_color)
        
        # Draw connection lines to center
        center_x, center_y = size//2, size//2
        draw.line([node_x, node_y, center_x, center_y], 
                 fill=secondary_color, width=2)
    
    return img

def main():
    """Create and save the icon in multiple sizes."""
    
    # Create the base icon
    icon = create_netsecurex_icon()
    
    # Save in different sizes
    sizes = [16, 32, 48, 64, 128, 256, 512]
    
    for size in sizes:
        resized = icon.resize((size, size), Image.Resampling.LANCZOS)
        resized.save(f'gui/assets/icons/netsecurex_{size}.png')
        print(f"Created icon: netsecurex_{size}.png")
    
    # Save as ICO file for Windows
    icon.save('gui/assets/icons/netsecurex.ico', format='ICO', 
              sizes=[(16,16), (32,32), (48,48), (64,64), (128,128), (256,256)])
    print("Created icon: netsecurex.ico")
    
    # Save main PNG
    icon.save('gui/assets/icons/netsecurex.png')
    print("Created icon: netsecurex.png")

if __name__ == "__main__":
    main()
