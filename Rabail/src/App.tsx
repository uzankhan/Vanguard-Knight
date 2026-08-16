import React, { useState, useEffect, useRef } from 'react';
import BackgroundAnimation from './BackgroundAnimation';

// @ts-ignore
const { electronAPI } = window;
import { HandLandmarker, FilesetResolver } from '@mediapipe/tasks-vision';

const App: React.FC = () => {
  const [isActive, setIsActive] = useState(false);
  const [gestureStatus, setGestureStatus] = useState('🖐️ Standby');
  const [gestureName, setGestureName] = useState('Standby');
  const [cameraError, setCameraError] = useState<string | null>(null);
  const [modelReady, setModelReady] = useState(false);
  const videoRef = useRef<HTMLVideoElement>(null);
  const handLandmarkerRef = useRef<any>(null);

  // Smoothing
  const prevPositions = useRef<{x: number, y: number}[]>([]);
  const gestureHistory = useRef<{action: string, name: string}[]>([]);
  const frameCounter = useRef(0);
  const PROCESS_EVERY_N_FRAMES = 3;
  const lastPosition = useRef({ x: 50, y: 50 });

  // Smooth Position
  const smoothPosition = (x: number, y: number) => {
    const windowSize = 5;
    prevPositions.current.push({x, y});
    if (prevPositions.current.length > windowSize) prevPositions.current.shift();
    const avgX = prevPositions.current.reduce((s, p) => s + p.x, 0) / prevPositions.current.length;
    const avgY = prevPositions.current.reduce((s, p) => s + p.y, 0) / prevPositions.current.length;
    return { x: avgX, y: avgY };
  };

  // Stabilize Gesture
  const stabilizeGesture = (newGesture: { action: string, name: string }) => {
    const historySize = 3;
    gestureHistory.current.push(newGesture);
    if (gestureHistory.current.length > historySize) gestureHistory.current.shift();
    
    const counts: Record<string, number> = {};
    gestureHistory.current.forEach(g => {
      const key = g.action + '|' + g.name;
      counts[key] = (counts[key] || 0) + 1;
    });
    
    let maxCount = 0;
    let mostFrequent = gestureHistory.current[gestureHistory.current.length - 1];
    for (const [key, count] of Object.entries(counts)) {
      if (count > maxCount) {
        maxCount = count;
        const [action, name] = key.split('|');
        mostFrequent = { action, name };
      }
    }
    
    if (maxCount / historySize > 0.6) {
      return mostFrequent;
    }
    return newGesture;
  };

  // ----- New Gesture Logic (All variables used, wrist included) -----
  const detectNewGesture = (landmarks: any[]) => {
    const THUMB_TIP = 4, INDEX_TIP = 8, INDEX_PIP = 6, MIDDLE_TIP = 12, MIDDLE_PIP = 10;
    const RING_TIP = 16, RING_PIP = 14, PINKY_TIP = 20, PINKY_PIP = 18, WRIST = 0;
    const INDEX_MCP = 5, MIDDLE_MCP = 9, RING_MCP = 13, PINKY_MCP = 17;

    // Extract all landmarks
    const thumbTip = landmarks[THUMB_TIP];
    const indexTip = landmarks[INDEX_TIP];
    const indexPip = landmarks[INDEX_PIP];
    const middleTip = landmarks[MIDDLE_TIP];
    const middlePip = landmarks[MIDDLE_PIP];
    const ringTip = landmarks[RING_TIP];
    const ringPip = landmarks[RING_PIP];
    const pinkyTip = landmarks[PINKY_TIP];
    const pinkyPip = landmarks[PINKY_PIP];
    const wrist = landmarks[WRIST];           // ✅ Now used
    const indexMcp = landmarks[INDEX_MCP];
    const middleMcp = landmarks[MIDDLE_MCP];
    const ringMcp = landmarks[RING_MCP];
    const pinkyMcp = landmarks[PINKY_MCP];

    // All distances (wristToIndex added)
    const pinchDist = Math.hypot(thumbTip.x - indexTip.x, thumbTip.y - indexTip.y);
    const indexMiddleDist = Math.hypot(indexTip.x - middleTip.x, indexTip.y - middleTip.y);
    const middleRingDist = Math.hypot(middleTip.x - ringTip.x, middleTip.y - ringTip.y);
    const ringPinkyDist = Math.hypot(ringTip.x - pinkyTip.x, ringTip.y - pinkyTip.y);
    const indexToMcp = Math.hypot(indexTip.x - indexMcp.x, indexTip.y - indexMcp.y);
    const middleToMcp = Math.hypot(middleTip.x - middleMcp.x, middleTip.y - middleMcp.y);
    const ringToMcp = Math.hypot(ringTip.x - ringMcp.x, ringTip.y - ringMcp.y);
    const pinkyToMcp = Math.hypot(pinkyTip.x - pinkyMcp.x, pinkyTip.y - pinkyMcp.y);
    const indexCurl = Math.hypot(indexTip.x - indexPip.x, indexTip.y - indexPip.y);
    const middleCurl = Math.hypot(middleTip.x - middlePip.x, middleTip.y - middlePip.y);
    const ringCurl = Math.hypot(ringTip.x - ringPip.x, ringTip.y - ringPip.y);
    const pinkyCurl = Math.hypot(pinkyTip.x - pinkyPip.x, pinkyTip.y - pinkyPip.y);
    const wristToIndex = Math.hypot(wrist.x - indexTip.x, wrist.y - indexTip.y); // ✅ Used

    // Finger extensions
    const isIndexExtended = indexToMcp > 0.03 && indexCurl > 0.02;
    const isMiddleExtended = middleToMcp > 0.03 && middleCurl > 0.02;
    const isRingExtended = ringToMcp > 0.03 && ringCurl > 0.02;
    const isPinkyExtended = pinkyToMcp > 0.03 && pinkyCurl > 0.02;

    const extendedFingers = [isIndexExtended, isMiddleExtended, isRingExtended, isPinkyExtended].filter(Boolean).length;

    // Spread / closed detection
    const isSpread = indexMiddleDist > 0.05 && middleRingDist > 0.05 && ringPinkyDist > 0.05;
    const fingerTips = [indexTip, middleTip, ringTip, pinkyTip];
    let tipDistSum = 0, tipCount = 0;
    for (let i = 0; i < fingerTips.length; i++) {
      for (let j = i + 1; j < fingerTips.length; j++) {
        tipDistSum += Math.hypot(fingerTips[i].x - fingerTips[j].x, fingerTips[i].y - fingerTips[j].y);
        tipCount++;
      }
    }
    const avgTipDistance = tipCount > 0 ? tipDistSum / tipCount : 1;
    const isClosed = avgTipDistance < 0.04;

    // ---- Gesture Mappings (wristToIndex used in conditions) ----

    // 1. ✋ 5 Fingers Spread (Open Palm) -> DO NOTHING
    if (extendedFingers >= 4 && isSpread && wristToIndex > 0.08) {
      return { action: 'nothing', name: 'Open Palm (No Action)' };
    }

    // 2. ✊ 5 Fingers Closed (Fist) -> Minimize All
    if (extendedFingers === 0 && isClosed && pinchDist < 0.05) {
      return { action: 'minimizeAll', name: 'Fist (Minimize All)' };
    }

    // 3. ✋ Open from Closed -> Zoom In
    if (extendedFingers >= 3 && isSpread && !isClosed && wristToIndex > 0.07) {
      return { action: 'zoomIn', name: 'Open Hand (Zoom In)' };
    }

    // 4. 🤏 4 Fingers Together + Swipe -> Next/Prev Tab
    if (extendedFingers >= 3 && !isSpread && !isClosed) {
      const handSpeedX = Math.abs(indexTip.x - indexMcp.x);
      if (handSpeedX > 0.025) {
        if (indexTip.x < indexMcp.x) {
          return { action: 'nextTab', name: '4-Finger Swipe Right' };
        } else {
          return { action: 'prevTab', name: '4-Finger Swipe Left' };
        }
      }
    }

    // 5. ✌️ Two fingers pointing -> Click
    if (isIndexExtended && isMiddleExtended && !isRingExtended && !isPinkyExtended) {
      const verticalSpeed = indexTip.y - indexPip.y;
      if (verticalSpeed > 0.02) {
        return { action: 'click', name: 'Two-Finger Tap (Click)' };
      }
      return { action: 'move', name: 'Two-Finger Point' };
    }

    // 6. 👆 Index pointing only -> Mouse Move
    if (isIndexExtended && !isMiddleExtended && !isRingExtended && !isPinkyExtended && pinchDist > 0.05) {
      return { action: 'move', name: 'Index Point (Move)' };
    }

    // 7. 🤏 Thumb + Index Pinch -> Drag
    if (pinchDist < 0.045 && isIndexExtended) {
      return { action: 'drag', name: 'Pinch Drag' };
    }

    // 8. 👋 Palm Push -> Show Desktop (uses wristToIndex)
    if (extendedFingers >= 4 && isSpread && !isClosed && wristToIndex > 0.09) {
      const handSpeedY = Math.abs(indexTip.y - indexMcp.y);
      if (handSpeedY > 0.03) {
        return { action: 'showDesktop', name: 'Palm Push (Show Desktop)' };
      }
    }

    // 9. ✊ Fist + Swipe -> Close Window
    if (extendedFingers === 0 && isClosed && pinchDist < 0.05) {
      const handSpeedX = Math.abs(indexTip.x - indexMcp.x);
      if (handSpeedX > 0.02) {
        if (indexTip.x < indexMcp.x) {
          return { action: 'closeWindow', name: 'Fist Swipe Left (Close)' };
        }
      }
    }

    // Default
    return { action: 'move', name: 'Pointer Move' };
  };

  // ----- Hand Tracking Setup -----
  useEffect(() => {
    const initHandTracking = async () => {
      try {
        const vision = await FilesetResolver.forVisionTasks(
          'https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision/wasm'
        );
        const handLandmarker = await HandLandmarker.createFromOptions(vision, {
          baseOptions: {
            modelAssetPath: '/hand_landmarker.task',
            delegate: 'GPU'
          },
          runningMode: 'VIDEO',
          numHands: 2
        });
        handLandmarkerRef.current = handLandmarker;
        setModelReady(true);
        setGestureStatus('✅ Model Loaded');
      } catch (error) {
        try {
          const vision = await FilesetResolver.forVisionTasks(
            'https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision/wasm'
          );
          const handLandmarker = await HandLandmarker.createFromOptions(vision, {
            baseOptions: {
              modelAssetPath: 'https://storage.googleapis.com/mediapipe-models/hand_landmarker/hand_landmarker/float16/1/hand_landmarker.task',
              delegate: 'GPU'
            },
            runningMode: 'VIDEO',
            numHands: 2
          });
          handLandmarkerRef.current = handLandmarker;
          setModelReady(true);
          setGestureStatus('✅ Model Loaded (Online)');
        } catch (fallbackError) {
          setGestureStatus('❌ Model Error');
        }
      }
    };
    initHandTracking();
  }, []);

  // ----- Camera Setup -----
  useEffect(() => {
    if (isActive) {
      navigator.mediaDevices.getUserMedia({ 
        video: { facingMode: 'user', width: { ideal: 640 }, height: { ideal: 480 } } 
      })
      .then((stream) => {
        if (videoRef.current) {
          videoRef.current.srcObject = stream;
          videoRef.current.onloadedmetadata = () => {
            videoRef.current?.play();
            setGestureStatus('📷 Camera Ready');
          };
        }
      })
      .catch((err) => {
        setCameraError(err.message);
        setGestureStatus('❌ Camera Error');
      });
    } else {
      if (videoRef.current && videoRef.current.srcObject) {
        const stream = videoRef.current.srcObject as MediaStream;
        stream.getTracks().forEach(track => track.stop());
        videoRef.current.srcObject = null;
      }
    }
  }, [isActive]);

  // ----- Detection Loop (Runs even when minimized) -----
  useEffect(() => {
    if (!isActive || !videoRef.current || !handLandmarkerRef.current || !modelReady) return;

    let animationId: number;

    const detectHand = async () => {
      const video = videoRef.current;
      if (!video || video.readyState < 2 || video.paused) {
        animationId = requestAnimationFrame(detectHand);
        return;
      }

      frameCounter.current++;
      if (frameCounter.current % PROCESS_EVERY_N_FRAMES !== 0) {
        animationId = requestAnimationFrame(detectHand);
        return;
      }

      try {
        const results = handLandmarkerRef.current.detectForVideo(video, performance.now());
        if (results.landmarks && results.landmarks.length > 0) {
          const landmarks = results.landmarks[0];
          const indexTip = landmarks[8];
          const rawX = indexTip.x * 100;
          const rawY = indexTip.y * 100;
          const { x, y } = smoothPosition(rawX, rawY);
          lastPosition.current = { x, y };

          const detected = detectNewGesture(landmarks);
          const stabilized = stabilizeGesture(detected);

          setGestureName(stabilized.name);
          setGestureStatus(`🖐️ ${stabilized.name}`);

          if (electronAPI && stabilized.action !== 'nothing') {
            electronAPI.sendGesture({ x, y, action: stabilized.action });
          }
        } else {
          setGestureName('No Hand');
          setGestureStatus('🖐️ No Hand');
        }
      } catch (error) {}
      animationId = requestAnimationFrame(detectHand);
    };

    detectHand();
    return () => { if (animationId) cancelAnimationFrame(animationId); };
  }, [isActive, modelReady]);

  const handleActivate = () => {
    const newStatus = !isActive;
    setIsActive(newStatus);
    setGestureStatus(newStatus ? '✅ Starting...' : '⏸️ Paused');
    setGestureName(newStatus ? 'Ready' : 'Paused');
    if (electronAPI) electronAPI.toggleGesture(newStatus);
  };

  // Cat logo path (put your image in public/logo-cat.png)
  const catLogo = '/logo-cat.png';

  return (
    <div style={styles.container}>
      <BackgroundAnimation />
      <div style={styles.menuBar}>
        <div style={styles.logoContainer}>
          <img src={catLogo} alt="Rabail" style={styles.logoImage} />
          <span style={styles.logoText}>✦ RABAIL OS</span>
        </div>
        <span style={styles.subLogo}>Responsive Autonomous Brain & Artificial Intelligence Logic</span>
        <span style={styles.status}>{gestureStatus}</span>
        <div style={styles.windowControls}>
          <button onClick={() => electronAPI?.minimizeWindow()} style={styles.controlBtn}>➖</button>
          <button onClick={() => electronAPI?.maximizeWindow()} style={styles.controlBtn}>⬜</button>
          <button onClick={() => electronAPI?.closeWindow()} style={{...styles.controlBtn, color: '#ff5f5f'}}>✕</button>
        </div>
      </div>

      <div style={styles.centerContent}>
        <h1 style={styles.title}>RABAIL Protocol</h1>
        <p style={styles.subtitle}>Control your entire Windows PC with hand gestures</p>
        <div style={styles.gestureDisplay}>
          <span style={styles.gestureName}>Gesture: {gestureName}</span>
        </div>
        {cameraError && <div style={styles.errorMsg}>⚠️ {cameraError}</div>}
        <button style={styles.activateBtn} onClick={handleActivate}>
          {isActive ? '🔴 DEACTIVATE' : '🟢 ACTIVATE'}
        </button>
        <div style={styles.gestureHint}>
          ✊ Fist = Minimize | ✋ Open = Zoom In | ✌️ Tap = Click | 👆 Point = Move
        </div>
        <div style={styles.cameraStatus}>
          {isActive ? '📷 Camera Active' : '📷 Camera Off'}
        </div>
      </div>

      <video ref={videoRef} style={{ display: 'none' }} autoPlay playsInline />
    </div>
  );
};

// ----- Styles -----
const styles: { [key: string]: React.CSSProperties } = {
  container: {
    width: '100vw',
    height: '100vh',
    backgroundColor: '#FFFFFF',
    display: 'flex',
    flexDirection: 'column',
    color: '#2C2C2C',
    fontFamily: 'Segoe UI, sans-serif',
    position: 'relative',
    overflow: 'hidden',
  },
  menuBar: {
    height: '60px',
    backgroundColor: 'rgba(255, 182, 193, 0.3)',
    backdropFilter: 'blur(10px)',
    display: 'flex',
    justifyContent: 'space-between',
    padding: '0 25px',
    alignItems: 'center',
    borderBottom: '2px solid #FFB6C1',
    zIndex: 10,
    position: 'relative',
  },
  logoContainer: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  logoImage: {
    width: '36px',
    height: '36px',
    borderRadius: '50%',
    objectFit: 'cover',
  },
  logoText: { fontWeight: 'bold', color: '#FF69B4', fontSize: '24px' },
  subLogo: { fontSize: '12px', color: '#888888', marginLeft: '10px' },
  status: { fontSize: '14px', color: '#555555' },
  windowControls: { display: 'flex', gap: '8px', alignItems: 'center' },
  controlBtn: {
    background: 'transparent',
    border: 'none',
    color: '#888888',
    fontSize: '18px',
    width: '30px',
    height: '30px',
    borderRadius: '50%',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    transition: 'all 0.2s',
  },
  centerContent: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'center',
    alignItems: 'center',
    zIndex: 5,
    gap: '15px',
    position: 'relative',
  },
  title: {
    fontSize: '72px',
    fontWeight: '300',
    background: 'linear-gradient(135deg, #FF69B4, #FF1493)',
    WebkitBackgroundClip: 'text',
    WebkitTextFillColor: 'transparent',
    margin: 0,
  },
  subtitle: { fontSize: '20px', color: '#666666', marginTop: '-10px' },
  gestureDisplay: {
    padding: '10px 30px',
    backgroundColor: 'rgba(255, 182, 193, 0.2)',
    borderRadius: '20px',
    border: '2px solid #FFB6C1',
  },
  gestureName: { fontSize: '18px', color: '#FF69B4', fontWeight: 'bold' },
  errorMsg: {
    padding: '10px 20px',
    backgroundColor: '#FFE0E0',
    borderRadius: '10px',
    color: '#CC0000',
    border: '1px solid #FF0000',
    fontSize: '14px',
  },
  activateBtn: {
    padding: '18px 60px',
    fontSize: '24px',
    fontWeight: 'bold',
    backgroundColor: '#FFB6C1',
    color: '#FFFFFF',
    border: 'none',
    borderRadius: '50px',
    cursor: 'pointer',
    boxShadow: '0 0 40px rgba(255, 182, 193, 0.5)',
    transition: 'all 0.3s',
    marginTop: '10px',
  },
  gestureHint: {
    marginTop: '20px',
    padding: '15px 30px',
    backgroundColor: 'rgba(255, 182, 193, 0.1)',
    borderRadius: '20px',
    color: '#666666',
    border: '2px solid #FFB6C1',
    fontSize: '16px',
  },
  cameraStatus: {
    marginTop: '5px',
    fontSize: '14px',
    color: '#999999',
  },
};

export default App;