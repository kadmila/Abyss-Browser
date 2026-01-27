//using System.Collections.Concurrent;

//namespace AbyssCLI.AML
//{
//    internal class IsolatedElemChecker : IDisposable
//    {
//        private readonly ConcurrentQueue<Element> _queue;
//        public void Checkout(Element element) =>
//            _queue.Enqueue(element);
//        public void Filter()
//        {
//            List<Element> remaining = [];
//            var count = _queue.Count;
//            for(var i = 0; i < count; i++)
//            {
//                if (!_queue.TryDequeue(out var element))
//                    break;

//                //we assume that while adding child, the reference always stays alive.
//                //therefore, this condition means the element is not referenced in JavaScript(strong),
//                //and also not attached to DOM.
//                //Dispose()may be called multiple times for an element.
//                if (!element.Rc.DoRefExist && element.Parent == null)
//                {
//                    element.Dispose();
//                }
//                else
//                {
//                    remaining.Add(element);
//                }
//            }
//            foreach(var rem in remaining)
//                _queue.Enqueue(rem);
//        }
//        public void Dispose()
//        {
//            foreach(var element in _queue)
//                element.Dispose();
//            _queue.Clear();
//        }
//    }

//}
