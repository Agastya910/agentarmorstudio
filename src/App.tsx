import Dashboard from "./pages/Dashboard";
import UpdateNotification from "./components/UpdateNotification";
import SidecarCrashBanner from "./components/SidecarCrashBanner";
import "./index.css";

function App() {
  return (
    <>
      <SidecarCrashBanner />
      <Dashboard />
      <UpdateNotification />
    </>
  );
}

export default App;
