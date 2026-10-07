import { Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import Layout from './components/Layout';
import Schedule from './pages/Schedule';
import Requests from './pages/Requests';
import Notifications from './pages/Notifications';
import Admin from './pages/Admin';
import Profile from './pages/Profile';

function Protected({ children }) {
  return localStorage.getItem('token') ? children : <Navigate to="/login" replace />;
}

export default function App() {
  const user = JSON.parse(localStorage.getItem('user') || '{}');
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<Protected><Layout /></Protected>}>
        <Route index element={<Schedule />} />
        <Route path="requests" element={<Requests />} />
        <Route path="notifications" element={<Notifications />} />
        <Route path="admin" element={user.roles === 'admin' ? <Admin /> : <Navigate to="/profile" />} />
        <Route path="profile" element={<Profile />} />
      </Route>
      <Route path="*" element={<Navigate to="/" />} />
    </Routes>
  );
}
