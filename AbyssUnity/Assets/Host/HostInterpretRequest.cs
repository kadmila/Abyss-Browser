using AbyssCLI.ABI;
using Google.Protobuf;
using System;

#nullable enable
namespace Host
{
    partial class Host
    {
        private void Init()
        {
            clientUtils.InputManager.AddressBarSubmitCallback = Tx.MoveWorld;
            clientUtils.InputManager.SubAddressBarSubmitCallback = (arg) =>
            {
                if (arg == "")
                    return;

                if (!(arg.StartsWith("abyst://") || arg.StartsWith("https://") || arg.StartsWith("http://")))
                {
                    arg = "https://" + arg;
                }

                var camera_transform = clientUtils.CameraTransform;
                var new_uuid = Guid.NewGuid();
                Tx.ShareContent(
                    ByteString.CopyFrom(new_uuid.ToByteArray()),
                    arg,
                    new Vec3 { X = camera_transform.localPosition.x, Y = camera_transform.localPosition.y, Z = camera_transform.localPosition.z },
                    new Vec4 { W = camera_transform.localRotation.w, X = camera_transform.localRotation.x, Y = camera_transform.localRotation.y, Z = camera_transform.localRotation.z }
                );
            };
            clientUtils.InputManager.WorldConsoleSubmitCallback = (arg) => Tx.ConsoleInput(0, arg);
            clientUtils.InputManager.LocalItemIconCloseCallback = (uuid) =>
                Tx.UnshareContent(ByteString.CopyFrom(uuid.ToByteArray()));

            _static_resource_loader.SynchronizedActionEnqueueCallback =
                RenderingActionQueue.Enqueue;
        }

        private void InterpretRequest(RenderAction render_action)
        {
            switch (render_action.InnerCase)
            {
            case RenderAction.InnerOneofCase.ConsolePrint: clientUtils.UIManager.AppendConsole(render_action.ConsolePrint.Text);return;
            case RenderAction.InnerOneofCase.CreateElement: RenderingActionQueue.Enqueue(() => sceneManager.CreateElement(render_action.CreateElement));return;
            case RenderAction.InnerOneofCase.MoveElement: RenderingActionQueue.Enqueue(() => sceneManager.MoveElement(render_action.MoveElement));return;
            case RenderAction.InnerOneofCase.DeleteElement: RenderingActionQueue.Enqueue(() => sceneManager.DeleteElement(render_action.DeleteElement));return;
            case RenderAction.InnerOneofCase.ElemSetActive: RenderingActionQueue.Enqueue(() => sceneManager.ElemSetActive(render_action.ElemSetActive));return;
            case RenderAction.InnerOneofCase.ElemSetTransform: RenderingActionQueue.Enqueue(() => sceneManager.ElemSetTransform(render_action.ElemSetTransform));return;
            case RenderAction.InnerOneofCase.ElemAttachResource: ElemAttachResource(render_action.ElemAttachResource);return;
            case RenderAction.InnerOneofCase.ElemDetachResource: ElemDetachResource(render_action.ElemDetachResource);return;
            case RenderAction.InnerOneofCase.ElemSetValueF: ElemSetValueF(render_action.ElemSetValueF);return;
            case RenderAction.InnerOneofCase.CreateItem: RenderingActionQueue.Enqueue(CreateItem(render_action.CreateItem));return;
            case RenderAction.InnerOneofCase.DeleteItem: RenderingActionQueue.Enqueue(DeleteItem(render_action.DeleteItem));return;
            case RenderAction.InnerOneofCase.ItemSetTitle: RenderingActionQueue.Enqueue(ItemSetTitle(render_action.ItemSetTitle));return;
            case RenderAction.InnerOneofCase.ItemSetIcon: RenderingActionQueue.Enqueue(ItemSetIcon(render_action.ItemSetIcon));return;
            case RenderAction.InnerOneofCase.ItemSetActive: RenderingActionQueue.Enqueue(ItemSetActive(render_action.ItemSetActive));return;
            case RenderAction.InnerOneofCase.ItemAlert: RenderingActionQueue.Enqueue(ItemAlert(render_action.ItemAlert));return;
            case RenderAction.InnerOneofCase.OpenStaticResource: OpenStaticResource(render_action.OpenStaticResource);return;
            case RenderAction.InnerOneofCase.CreateCompositeResource: RenderingActionQueue.Enqueue(CreateCompositeResource(render_action.CreateCompositeResource));return;
            case RenderAction.InnerOneofCase.CloseResource: RenderingActionQueue.Enqueue(CloseResource(render_action.CloseResource));return;
            case RenderAction.InnerOneofCase.MemberInfo: RenderingActionQueue.Enqueue(MemberInfo(render_action.MemberInfo));return;
            case RenderAction.InnerOneofCase.MemberLeave: RenderingActionQueue.Enqueue(MemberLeave(render_action.MemberLeave));return;
            case RenderAction.InnerOneofCase.MemberSetProfile: RenderingActionQueue.Enqueue(MemberSetProfile(render_action.MemberSetProfile));return;
            case RenderAction.InnerOneofCase.LocalInfo: RenderingActionQueue.Enqueue(LocalInfo(render_action.LocalInfo));return;
            case RenderAction.InnerOneofCase.InfoContentShared: RenderingActionQueue.Enqueue(InfoContentShared(render_action.InfoContentShared));return;
            case RenderAction.InnerOneofCase.InfoContentDeleted: RenderingActionQueue.Enqueue(InfoContentDeleted(render_action.InfoContentDeleted));return;
            default: clientUtils.UIManager.AppendConsole("Executor: invalid RenderAction: " + render_action.InnerCase);return;
            }
        }
        private void ElemAttachResource(RenderAction.Types.ElemAttachResource args)
        {
            if (!_static_resource_loader.TryGetValue(args.ResourceId, out var resource))
                throw new Exception("ElemAttachResource: resource not found");

            RenderingActionQueue.Enqueue(
                () => sceneManager.GetElement(args.ElementId).AttachResource(args.ResourceId, resource, args.Role));
        }
        private void ElemDetachResource(RenderAction.Types.ElemDetachResource args) =>
            RenderingActionQueue.Enqueue(() => sceneManager.GetElement(args.ElementId).DetachResource(args.ResourceId));
        private void ElemSetValueF(RenderAction.Types.ElemSetValueF args) =>
            RenderingActionQueue.Enqueue(() => sceneManager.GetElement(args.ElementId).SetValueF(args.Role, args.Value));
        private Action CreateItem(RenderAction.Types.CreateItem args) => () =>
        {
            if (args.SharerHash == clientUtils.LocalHash)
            {
                clientUtils.UIManager.LocalItemSection.AddItem(args.ElementId, new Guid(args.Uuid.Span));
            }
            else
            {
                clientUtils.UIManager.AppendConsole("member item UI not implemented 1");
            }
        };
        private Action DeleteItem(RenderAction.Types.DeleteItem args) => () =>
        {
            if (clientUtils.UIManager.LocalItemSection.TryRemoveItem(args.ElementId)) 
                return;

            clientUtils.UIManager.AppendConsole("member item UI not implemented 2");
        };
        private Action ItemSetTitle(RenderAction.Types.ItemSetTitle args) => () => { };
        private Action ItemSetIcon(RenderAction.Types.ItemSetIcon args)
        {
            bool is_clear = args.ElementId == 0;
            StaticResource? resource = null;
            if (!is_clear && !_static_resource_loader.TryGetValue(args.ResourceId, out resource))
                throw new InvalidOperationException("resource not found");

            if (args.ElementId == 0) //world environment
            {
                if (is_clear) //default icon
                    return clientUtils.UIManager.ClearWorldIcon;

                return resource switch
                {
                    Image image => () => clientUtils.UIManager.SetWorldIcon(image.Texture),
                    _ => () => { }
                };
            }

            return () =>
            {
                if (is_clear)
                {
                    if (clientUtils.UIManager.LocalItemSection.TryUpdateIcon(args.ElementId, clientUtils.UIResources.DefaultItemIcon))
                        return;

                    clientUtils.UIManager.AppendConsole("member item UI not implemented 3");
                }
                else
                {
                    if (clientUtils.UIManager.LocalItemSection.TryUpdateIcon(args.ElementId, resource switch
                    {
                        Image image => image.Texture,
                        _ => clientUtils.UIResources.DefaultItemIcon
                    }))
                        return;

                    clientUtils.UIManager.AppendConsole("member item UI not implemented 4");
                }
            };
        }
        private Action ItemSetActive(RenderAction.Types.ItemSetActive args) => () => { };
        private Action ItemAlert(RenderAction.Types.ItemAlert args) => () => { };
        private void OpenStaticResource(RenderAction.Types.OpenStaticResource args)
        {
            StaticResource resource = args.Mime switch
            {
                MIME.ModelObj or MIME.ApplicationXTgif => new Mesh(args.FileName), //application/x-tgif is returned from legacy web servers that expect to serve x-11 .obj
                MIME.ImageJpeg or MIME.ImagePng => new Image(args.FileName),
                _ => new UnknownResource(args.FileName, args.Mime),
            };
            RenderingActionQueue.Enqueue(resource.Init);
            _static_resource_loader.Add(args.ResourceId, resource);
        }
        private Action CloseResource(RenderAction.Types.CloseResource args) => () => { };
        private Action CreateCompositeResource(RenderAction.Types.CreateCompositeResource args) => () => { };
        private Action MemberInfo(RenderAction.Types.MemberInfo args) => () => { };
        private Action MemberSetProfile(RenderAction.Types.MemberSetProfile args) => () => { };
        private Action MemberLeave(RenderAction.Types.MemberLeave args) => () => { };
        private Action LocalInfo(RenderAction.Types.LocalInfo args) => () =>
        {
            clientUtils.LocalHash = args.LocalHash;
            clientUtils.LocalHostAurl = args.Aurl;
            clientUtils.UIManager.SetLocalInfo(args.LocalHash);
        };
        private Action InfoContentShared(RenderAction.Types.InfoContentShared args) => () => { };
        private Action InfoContentDeleted(RenderAction.Types.InfoContentDeleted args) => () => { };

    }
}