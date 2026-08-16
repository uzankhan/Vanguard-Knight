export {};

declare global {
  interface Window {
    electronAPI: {
      toggleGesture: (status: boolean) => void;
      sendGesture: (data: { x: number; y: number; action: string }) => void;
      minimizeWindow: () => void;
      maximizeWindow: () => void;
      closeWindow: () => void;
    };
  }
}