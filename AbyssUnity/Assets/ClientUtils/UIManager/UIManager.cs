using System;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UIElements;

namespace ClientUtils.UIManager
{
    public enum FocusedTextField
    {
        None,
        MainAddressBar,
        SubAddressBar,
        Console,
    }
    public class UIManager
    {
        private readonly UIResources uiResources;
        private readonly UIDocument uiDocument;

        //internal uiDocument reference shortcuts
        private readonly VisualElement root;

        private readonly Button tabHomeButton;
        private readonly Button tabSocialButton;
        private readonly Button tabSettingsButton;
        private readonly Button tabDevButton;

        private readonly VisualElement home;
        private readonly VisualElement social;
        private readonly VisualElement settings;
        private readonly VisualElement dev;

        private readonly Image worldPic;
        private readonly Label worldTitle;
        private readonly Label worldURL;
        private readonly Button worldBookmarkButton;

        private readonly TextField mainAddressBar;
        private readonly TextField subAddressBar;

        private readonly VisualElement openItemsSection;
        private readonly VisualElement inventory;

        private readonly Label localId;
        private readonly Label frameTime;
        private readonly Label log;
        private readonly TextField console;

        //console 
        private bool _is_dev_active;
        private LinkedList<string> _console_lines;
        private bool _is_console_updated;

        //callback reservation
        public Action OnWorldBookmark = () => { };
        public Action<Guid> OnItemClose = a => { };

        //public lookup (due to stupid TextField thing, we need manual lookup)
        public string MainAddressBarText => mainAddressBar.text;
        public string SubAddressBarText => subAddressBar.text;
        public string ConsoleText => console.text;
        public FocusedTextField FocusedTextFieldName { get; private set; }

        public UIManager(UIResources UIResources, UIDocument UIDocument)
        {
            uiResources = UIResources;
            uiDocument = UIDocument;

            root = uiDocument.rootVisualElement;

            tabHomeButton = root.Q<Button>("tab-home-button");
            tabSocialButton = root.Q<Button>("tab-social-button");
            tabSettingsButton = root.Q<Button>("tab-settings-button");
            tabDevButton = root.Q<Button>("tab-dev-button");

            home = root.Q<VisualElement>("home");
            social = root.Q<VisualElement>("social");
            settings = root.Q<VisualElement>("settings");
            dev = root.Q< VisualElement>("dev");

            worldPic = root.Q<Image>("world-pic");
            worldTitle = root.Q<Label>("world-title");
            worldURL = root.Q<Label>("world-url");
            worldBookmarkButton = root.Q<Button>("world-bookmark-button");

            mainAddressBar = root.Q<TextField>("main-address-bar");
            subAddressBar = root.Q<TextField>("sub-address-bar");

            openItemsSection = root.Q<VisualElement>("open-items-section");
            inventory = root.Q< VisualElement>("inventory");

            localId = root.Q<Label>("local-id");
            frameTime = root.Q<Label>("frame-time");
            log = root.Q<Label>("log");
            console = root.Q<TextField>("console");

            //register callbacks
            tabHomeButton.clicked += () => ChangeTabContent(home, tabHomeButton);
            tabSocialButton.clicked += () => ChangeTabContent(social, tabSocialButton);
            tabSettingsButton.clicked += () => ChangeTabContent(settings, tabSettingsButton);
            tabDevButton.clicked += () => ChangeTabContent(dev, tabDevButton);

            //check for text field focus
            mainAddressBar.RegisterCallback<FocusInEvent>(_ => FocusedTextFieldName = FocusedTextField.MainAddressBar);
            mainAddressBar.RegisterCallback<FocusOutEvent>(_ => FocusedTextFieldName = FocusedTextField.None);
            subAddressBar.RegisterCallback<FocusInEvent>(_ => FocusedTextFieldName = FocusedTextField.SubAddressBar);
            subAddressBar.RegisterCallback<FocusOutEvent>(_ => FocusedTextFieldName = FocusedTextField.None);
            console.RegisterCallback<FocusInEvent>(_ => FocusedTextFieldName = FocusedTextField.Console);
            console.RegisterCallback<FocusOutEvent>(_ => FocusedTextFieldName = FocusedTextField.None);

            worldBookmarkButton.clicked += () => OnWorldBookmark();

            _console_lines = new();
            _is_console_updated = false;
        }
        private void ChangeTabContent(VisualElement target, Button button)
        {
            home.style.display = DisplayStyle.None;
            social.style.display = DisplayStyle.None;
            settings.style.display = DisplayStyle.None;
            dev.style.display = DisplayStyle.None;

            tabHomeButton.RemoveFromClassList("tab-active");
            tabSocialButton.RemoveFromClassList("tab-active");
            tabSettingsButton.RemoveFromClassList("tab-active");
            tabDevButton.RemoveFromClassList("tab-active");

            target.style.display = DisplayStyle.Flex;
            button.AddToClassList("tab-active");

            _is_dev_active = false;
            if (target.name == "dev")
                _is_dev_active = true;
        }

        public void AppendLog(string line)
        {
            ClientLogger.WriteLine(line);

            lock (_console_lines)
            {
                _ = _console_lines.AddLast(line);
                if (_console_lines.Count == 100)
                {
                    _console_lines.RemoveFirst();
                }
                _is_console_updated = true;
            }
        }
        public void ClearConsole()
        {
            lock (_console_lines)
            {
                _console_lines.Clear();
                _is_console_updated = true;
            }
        }
        public void UnityUpdate()
        {
            if (_is_dev_active && _is_console_updated)
            {
                lock (_console_lines)
                {
                    log.text = string.Join("\n", _console_lines);
                    _is_console_updated = false;
                }
            }
        }
        public void AddLocalItemIcon(int element_id, Guid uuid)
        {

        }
        public bool TryRemoveLocalItemIcon(int element_id)
        {
            return false;
        }
        public bool TryUpdateLocalItemIcon(int element_id, Texture2D icon)
        {
            return false;
        }

        public void Activate() => root.visible = true;
        public void Deactivate() => root.visible = false;
        public void SetWorldIcon(Texture2D texture) => worldPic.image = texture;
        public void ClearWorldIcon() => worldPic.image = uiResources.DefaultWorldPic;
        public void SetLocalInfo(string hash) => localId.text = "ID: " + hash;
        public void SetFrameTime(string info) => frameTime.text = info;
    }
}
