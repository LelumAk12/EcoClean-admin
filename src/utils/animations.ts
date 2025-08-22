// Standard animation configurations for consistent UI animations across all manager components

export const pageAnimations = {
  // Standard page entrance animation
  container: {
    initial: { opacity: 0 },
    animate: { opacity: 1 },
    transition: { duration: 0.3 }
  },
  
  // Header section animation
  header: {
    initial: { opacity: 0, y: 20 },
    animate: { opacity: 1, y: 0 },
    transition: { duration: 0.5, delay: 0.1 }
  },
  
  // Stats cards animation with staggered delays
  statsCard: (index: number) => ({
    initial: { opacity: 0, y: 20 },
    animate: { opacity: 1, y: 0 },
    transition: { duration: 0.5, delay: 0.2 + (index * 0.1) }
  }),
  
  // Main content area animation
  mainContent: {
    initial: { opacity: 0, y: 20 },
    animate: { opacity: 1, y: 0 },
    transition: { duration: 0.5, delay: 0.6 }
  },
  
  // Individual item animations (for cards, table rows, etc.)
  item: (index: number) => ({
    initial: { opacity: 0, y: 20 },
    animate: { opacity: 1, y: 0 },
    transition: { duration: 0.3, delay: index * 0.05 }
  }),
  
  // Modal animations
  modal: {
    initial: { opacity: 0, scale: 0.95 },
    animate: { opacity: 1, scale: 1 },
    exit: { opacity: 0, scale: 0.95 },
    transition: { duration: 0.2 }
  },
  
  // Hover animations for interactive elements
  hover: {
    whileHover: { y: -2, scale: 1.02 },
    transition: { duration: 0.2 }
  }
};

// Toast animation configuration
export const toastAnimations = {
  initial: { opacity: 0, x: 300, scale: 0.8 },
  animate: { opacity: 1, x: 0, scale: 1 },
  exit: { opacity: 0, x: 300, scale: 0.8 },
  transition: { duration: 0.3, ease: "easeOut" }
};
