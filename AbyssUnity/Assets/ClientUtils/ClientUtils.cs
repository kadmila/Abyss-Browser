using System.Runtime.CompilerServices;
using System.Threading;
using UnityEditor;
using UnityEngine;
using UnityEngine.UIElements;
using static UnityEditor.SceneView;

namespace ClientUtils
{ 
    public class ClientUtils : MonoBehaviour
    {
        //internals
        private int unityThreadID = 0;
        private MainInputActions MainInputActions;

        //singleton
        private static ClientUtils staticInstance;
        public static ClientUtils GetInstance() => staticInstance;

        //inspecter
        public MaterialResources MaterialResources;
        public UIResources UIResources;
        public UIDocument UIDocument;
        public Transform PlayerTransform; //mutating rotation is for non-z gravity scenario
        public Transform CameraTransform; //only rotation
        public float PlayerMoveSpeed;
        public float CameraRotationSpeed;


        //exposed members
        [HideInInspector] public string LocalHash;
        [HideInInspector] public string LocalHostAurl;
        [HideInInspector] public RenderingPrimitives.MaterialLoader MaterialLoader { get; private set; }
        [HideInInspector] public UIManager.UIManager UIManager { get; private set; }
        [HideInInspector] public InputManager.InputManager InputManager { get; private set; }

        public void AssertIsUnityThread(
            [CallerMemberName] string memberName = "",
            [CallerFilePath] string filePath = "",
            [CallerLineNumber] int lineNumber = 0)
        {
#if UNITY_EDITOR
            if (unityThreadID == 0)
            {
                Debug.Log("AssertIsUnityThread: ClientUtils is not enabled yet");
                return;
            }

            if (Thread.CurrentThread.ManagedThreadId != unityThreadID)
            {
                Debug.Log($"This must be in unity main thread, but it isn't: {memberName} in {filePath}:{lineNumber}");
                EditorApplication.isPlaying = false;
            }
#endif
        }

        private void OnEnable()
        {
            unityThreadID = Thread.CurrentThread.ManagedThreadId;
            MainInputActions = new();

            staticInstance = this;

            MaterialLoader = new(MaterialResources);
            UIManager = new(UIResources, UIDocument);
            InputManager = new(MainInputActions, UIManager);
        }
        private void OnDisable()
        {
            staticInstance = null;

            MaterialLoader.Dispose();
            MaterialLoader = null;
            UIManager = null;
            InputManager.Dispose();
            InputManager = null;

            unityThreadID = 0;
            MainInputActions.Dispose();
            MainInputActions = null;
        }
        private void Update()
        {
            UIManager.UnityUpdate();

            UpdatePlayerTransform();
            UpdateCameraTransform();
        }
        private void UpdatePlayerTransform()
        {
            var amount = InputManager.MoveDelta;
            Vector3 forwardMovement = PlayerTransform.forward * amount.y;
            Vector3 rightMovement = PlayerTransform.right * amount.x;

            Vector3 movement = (forwardMovement + rightMovement) * PlayerMoveSpeed;
            PlayerTransform.position += movement;
        }
        private float pitch = 0.0f;  // Up/Down rotation (X-axis)
        private float yaw = 0.0f;    // Left/Right rotation (Y-axis)
        private void UpdateCameraTransform()
        {
            var amount = InputManager.ViewDelta;
            // Get the input and multiply by the rotation speed
            yaw += amount.x * CameraRotationSpeed;
            pitch -= amount.y * CameraRotationSpeed;

            // Clamp pitch to avoid looking too far up or down
            pitch = Mathf.Clamp(pitch, -90f, 90f);

            // Apply the rotation
            CameraTransform.localEulerAngles = new Vector3(pitch, yaw, 0f);
        }
    }
}