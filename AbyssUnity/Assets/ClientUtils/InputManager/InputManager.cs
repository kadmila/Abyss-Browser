using System;
using UnityEngine;
using UnityEngine.InputSystem;

namespace ClientUtils.InputManager
{ 
    public class InputManager : IDisposable
    {
        private MainInputActions inputActions;
        private UIManager.UIManager uiManager;

        private InputAction viewAction;
        private InputAction moveAction;

        //callback registration
        public Action<string> AddressBarSubmitCallback;
        public Action<string> SubAddressBarSubmitCallback;
        public Action<string> WorldConsoleSubmitCallback;
        public Action<Guid> LocalItemIconCloseCallback;

        //read (only valid in Update())
        public Vector2 ViewDelta => viewAction.ReadValue<Vector2>();
        public Vector2 MoveDelta => moveAction.ReadValue<Vector2>() * Time.deltaTime;

        // Start is called once before the first execution of Update after the MonoBehaviour is created
        public InputManager(MainInputActions MainInputActions, UIManager.UIManager UIManager)
        {
            inputActions = MainInputActions;
            uiManager = UIManager;

            viewAction = inputActions.Player.Look;
            moveAction = inputActions.Player.Move;

            inputActions.UI.Cancel.performed += OnUIExit;
            inputActions.UI.Submit.performed += OnUISubmit;

            inputActions.Player.OpenMenu.performed += OnUIEnter;

            inputActions.UI.Enable();
        }
        private void OnUIEnter(InputAction.CallbackContext ctx)
        {
            Cursor.visible = true;
            Cursor.lockState = CursorLockMode.None;
            inputActions.Player.Disable();
            inputActions.UI.Enable();
            uiManager.Activate();
        }
        private void OnUIExit(InputAction.CallbackContext ctx)
        {
            uiManager.Deactivate();
            inputActions.UI.Disable();
            inputActions.Player.Enable();
            Cursor.lockState = CursorLockMode.Locked;
            Cursor.visible = false;
        }

        private void OnUISubmit(InputAction.CallbackContext ctx)
        {
            AddressBarSubmitCallback(uiManager.AddressBarText);
        }

        public void Dispose()
        {
            inputActions.UI.Cancel.performed -= OnUIExit;
            inputActions.UI.Submit.performed -= OnUISubmit;

            inputActions.Player.OpenMenu.performed -= OnUIEnter;

            viewAction = null;
            moveAction = null;

            inputActions = null;
            uiManager = null;
        }
        ~InputManager() => Dispose();
    }

}