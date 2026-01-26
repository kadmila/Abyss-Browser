using UnityEngine;
using UnityEngine.InputSystem;

namespace GlobalDependency
{
    public class InteractionBase : MonoBehaviour
    {
        [SerializeField] private InputActionAsset actions;

        [SerializeField] private UIBase uiHandler;

        [SerializeField] private TemporalCameraMover cameraMover;

        [SerializeField] private Transform viewDirection;

        //main
        private InputAction viewAction;
        private InputAction moveAction;
        private InputAction jumpAction;
        private InputAction crouchAction;
        private InputAction enterUIAction;

        //ui
        private InputAction mainReturnAction;

        public Transform GetContentSpawnPos() => cameraMover.transform;
        private void Start()
        {
            Application.targetFrameRate = 120;
        }
        void Awake()
        {
            //main
            viewAction = actions.FindActionMap("main").FindAction("view", throwIfNotFound: true);
            moveAction = actions.FindActionMap("main").FindAction("move", throwIfNotFound: true);
            jumpAction = actions.FindActionMap("main").FindAction("jump", throwIfNotFound: true);
            crouchAction = actions.FindActionMap("main").FindAction("crouch", throwIfNotFound: true);
            enterUIAction = actions.FindActionMap("main").FindAction("enter_ui", throwIfNotFound: true);

            viewAction.Enable();
            moveAction.Enable();
            jumpAction.Enable();
            crouchAction.Enable();
            enterUIAction.Enable();

            jumpAction.performed += OnJump;
            crouchAction.performed += OnCrouch;
            enterUIAction.performed += OnUIEnter;

            //ui
            mainReturnAction = actions.FindActionMap("ui").FindAction("return", throwIfNotFound: true);

            mainReturnAction.Enable();

            mainReturnAction.performed += OnMainReturn;
        }
        void OnEnable()
        {
            OnUIEnter(new InputAction.CallbackContext());
            //actions.FindActionMap("main").Enable();
        }
        void Update()
        {
            Vector2 viewVector = viewAction.ReadValue<Vector2>();
            Vector3 moveVector = moveAction.ReadValue<Vector3>();
            if (viewVector != Vector2.zero)
            {
                cameraMover.Rotate(viewVector * Time.deltaTime);
            }
            if (moveVector != Vector3.zero)
            {
                cameraMover.Move(moveVector * Time.deltaTime);
            }

            //lookat
            Ray ray = new(viewDirection.position, viewDirection.forward);
            if (Physics.Raycast(ray, out RaycastHit hitInfo, 100f))
            {
                Debug.DrawLine(ray.origin, hitInfo.point, Color.red);
            }
            else
            {
                Debug.DrawRay(ray.origin, ray.direction * 100f, Color.green);
            }
        }
        private void OnJump(InputAction.CallbackContext context)
        {
            //Debug.Log("jump!");
        }
        private void OnCrouch(InputAction.CallbackContext context)
        {
            cameraMover.Reset();
            //Debug.Log("crouch!");
        }
        private void OnUIEnter(InputAction.CallbackContext context)
        {
            Cursor.visible = true;
            Cursor.lockState = CursorLockMode.None;
            actions.FindActionMap("main").Disable();
            actions.FindActionMap("ui").Enable();
            uiHandler.Activate();
        }

        //ui
        private void OnMainReturn(InputAction.CallbackContext context)
        {
            Cursor.lockState = CursorLockMode.Locked;
            Cursor.visible = false;
            uiHandler.Deactivate();
            actions.FindActionMap("ui").Disable();
            actions.FindActionMap("main").Enable();
        }
    }
}