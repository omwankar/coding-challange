import React, { useState, useEffect, createContext, useContext } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import axios from 'axios';
import './App.css';

// Components
import { Button } from './components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './components/ui/card';
import { Input } from './components/ui/input';
import { Label } from './components/ui/label';
import { Badge } from './components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs';
import { AlertCircle, Star, Users, Store, TrendingUp, Search, Filter, Eye, EyeOff, LogOut, Plus, Check, X, Mail, MapPin, User } from 'lucide-react';
import { toast, Toaster } from 'sonner';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from './components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './components/ui/select';
import { Textarea } from './components/ui/textarea';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Auth Context
const AuthContext = createContext();

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const storedToken = localStorage.getItem('token');
    const storedUser = localStorage.getItem('user');
    
    if (storedToken && storedUser) {
      try {
        const userData = JSON.parse(storedUser);
        setUser(userData);
        setToken(storedToken);
        axios.defaults.headers.common['Authorization'] = `Bearer ${storedToken}`;
      } catch (error) {
        console.error('Error parsing stored user data:', error);
        localStorage.removeItem('token');
        localStorage.removeItem('user');
      }
    }
    setLoading(false);
  }, []);

  const login = (userData, authToken) => {
    setUser(userData);
    setToken(authToken);
    localStorage.setItem('token', authToken);
    localStorage.setItem('user', JSON.stringify(userData));
    axios.defaults.headers.common['Authorization'] = `Bearer ${authToken}`;
    
    // Redirect based on user role
    setTimeout(() => {
      if (userData.role === 'system_admin') {
        window.location.href = '/admin';
      } else if (userData.role === 'normal_user') {
        window.location.href = '/dashboard';
      } else if (userData.role === 'store_owner') {
        window.location.href = '/store-dashboard';
      }
    }, 100);
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    delete axios.defaults.headers.common['Authorization'];
    window.location.href = '/login';
    toast.success('Logged out successfully');
  };

  const value = {
    user,
    token,
    login,
    logout,
    loading
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// Login Component
const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await axios.post(`${API}/auth/login`, {
        email,
        password
      });

      login(response.data.user, response.data.access_token);
      toast.success('Login successful!');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Login failed');
    }

    setLoading(false);
  };

  // Quick admin login for demo
  const handleAdminLogin = () => {
    setEmail('admin@storerate.com');
    setPassword('AdminPass123!');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-sky-50 to-indigo-100 flex items-center justify-center p-4">
      <Card className="w-full max-w-md shadow-2xl border-0 bg-white/90 backdrop-blur-sm">
        <CardHeader className="text-center">
          <CardTitle className="text-3xl font-bold text-gray-800">Store Rating System</CardTitle>
          <CardDescription className="text-gray-600">Login to your account</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleLogin} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email" className="text-sm font-medium">Email</Label>
              <Input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Enter your email"
                required
                data-testid="login-email"
                className="h-12"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password" className="text-sm font-medium">Password</Label>
              <div className="relative">
                <Input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  required
                  data-testid="login-password"
                  className="h-12 pr-12"
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-2 top-2 h-8 w-8 p-0"
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </Button>
              </div>
            </div>
            <Button 
              type="submit" 
              className="w-full h-12 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white font-semibold rounded-lg transition-all duration-200"
              disabled={loading}
              data-testid="login-submit"
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </Button>
          </form>
          
          <div className="mt-6 space-y-3">
            <div className="text-center">
              <span className="text-sm text-gray-500">Demo Account:</span>
            </div>
            <Button
              variant="outline"
              onClick={handleAdminLogin}
              className="w-full border-blue-200 text-blue-600 hover:bg-blue-50"
              data-testid="demo-admin-login"
            >
              Login as Admin
            </Button>
          </div>

          <div className="mt-6 text-center space-y-2">
            <p className="text-sm text-gray-600">
              Don't have an account?{' '}
              <Button variant="link" className="p-0 text-blue-600 font-semibold" onClick={() => window.location.href = '/register'}>
                Sign up here
              </Button>
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

// Register Component
const Register = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    address: '',
    password: '',
    confirmPassword: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const validateForm = () => {
    if (formData.name.length < 20 || formData.name.length > 60) {
      toast.error('Name must be between 20 and 60 characters');
      return false;
    }
    if (formData.address.length > 400) {
      toast.error('Address must be less than 400 characters');
      return false;
    }
    if (formData.password !== formData.confirmPassword) {
      toast.error('Passwords do not match');
      return false;
    }
    if (!/^(?=.*[A-Z])(?=.*[!@#$%^&*()_+\-=\[\]{}|;:,.<>?])/.test(formData.password)) {
      toast.error('Password must contain at least one uppercase letter and one special character');
      return false;
    }
    return true;
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) return;
    
    setLoading(true);

    try {
      const response = await axios.post(`${API}/auth/register`, {
        name: formData.name,
        email: formData.email,
        address: formData.address,
        password: formData.password
      });

      login(response.data.user, response.data.access_token);
      toast.success('Registration successful!');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Registration failed');
    }

    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-green-50 to-blue-100 flex items-center justify-center p-4">
      <Card className="w-full max-w-md shadow-2xl border-0 bg-white/90 backdrop-blur-sm">
        <CardHeader className="text-center">
          <CardTitle className="text-3xl font-bold text-gray-800">Join Our Platform</CardTitle>
          <CardDescription className="text-gray-600">Create your account to start rating stores</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleRegister} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Full Name (20-60 characters)</Label>
              <Input
                id="name"
                name="name"
                value={formData.name}
                onChange={handleChange}
                placeholder="Enter your full name"
                required
                data-testid="register-name"
                className="h-12"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="email">Email Address</Label>
              <Input
                id="email"
                name="email"
                type="email"
                value={formData.email}
                onChange={handleChange}
                placeholder="Enter your email"
                required
                data-testid="register-email"
                className="h-12"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="address">Address (Max 400 characters)</Label>
              <Textarea
                id="address"
                name="address"
                value={formData.address}
                onChange={handleChange}
                placeholder="Enter your address"
                required
                data-testid="register-address"
                className="min-h-20"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password (8-16 chars, 1 uppercase, 1 special)</Label>
              <div className="relative">
                <Input
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  value={formData.password}
                  onChange={handleChange}
                  placeholder="Enter your password"
                  required
                  data-testid="register-password"
                  className="h-12 pr-12"
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-2 top-2 h-8 w-8 p-0"
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </Button>
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="confirmPassword">Confirm Password</Label>
              <Input
                id="confirmPassword"
                name="confirmPassword"
                type="password"
                value={formData.confirmPassword}
                onChange={handleChange}
                placeholder="Confirm your password"
                required
                data-testid="register-confirm-password"
                className="h-12"
              />
            </div>
            <Button 
              type="submit" 
              className="w-full h-12 bg-gradient-to-r from-green-600 to-blue-600 hover:from-green-700 hover:to-blue-700 text-white font-semibold rounded-lg transition-all duration-200"
              disabled={loading}
              data-testid="register-submit"
            >
              {loading ? 'Creating Account...' : 'Create Account'}
            </Button>
          </form>
          
          <div className="mt-6 text-center">
            <p className="text-sm text-gray-600">
              Already have an account?{' '}
              <Button variant="link" className="p-0 text-blue-600 font-semibold" onClick={() => window.location.href = '/login'}>
                Sign in here
              </Button>
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

// Dashboard Components
const AdminDashboard = () => {
  const [stats, setStats] = useState({ total_users: 0, total_stores: 0, total_ratings: 0 });
  const [users, setUsers] = useState([]);
  const [stores, setStores] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      const [statsRes, usersRes, storesRes] = await Promise.all([
        axios.get(`${API}/admin/dashboard`),
        axios.get(`${API}/admin/users`),
        axios.get(`${API}/admin/stores`)
      ]);

      setStats(statsRes.data);
      setUsers(usersRes.data);
      setStores(storesRes.data);
    } catch (error) {
      toast.error('Failed to fetch dashboard data');
    }
    setLoading(false);
  };

  const approveStore = async (storeId) => {
    try {
      await axios.put(`${API}/admin/stores/${storeId}/approve`);
      toast.success('Store approved successfully');
      fetchDashboardData();
    } catch (error) {
      toast.error('Failed to approve store');
    }
  };

  const rejectStore = async (storeId) => {
    try {
      await axios.put(`${API}/admin/stores/${storeId}/reject`);
      toast.success('Store rejected');
      fetchDashboardData();
    } catch (error) {
      toast.error('Failed to reject store');
    }
  };

  const getStatusBadge = (status) => {
    const variants = {
      'pending': 'bg-yellow-100 text-yellow-800',
      'approved': 'bg-green-100 text-green-800',
      'rejected': 'bg-red-100 text-red-800'
    };
    return (
      <Badge className={variants[status] || 'bg-gray-100 text-gray-800'}>
        {status?.charAt(0).toUpperCase() + status?.slice(1)}
      </Badge>
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <h1 className="text-3xl font-bold text-gray-900" data-testid="admin-dashboard-title">Admin Dashboard</h1>
        </div>
      </div>
      
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="mb-8">
            <TabsTrigger value="overview" data-testid="overview-tab">Overview</TabsTrigger>
            <TabsTrigger value="users" data-testid="users-tab">Users</TabsTrigger>
            <TabsTrigger value="stores" data-testid="stores-tab">Stores</TabsTrigger>
          </TabsList>

          <TabsContent value="overview">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
              <Card className="bg-gradient-to-r from-blue-500 to-blue-600 text-white">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-blue-100">Total Users</p>
                      <p className="text-3xl font-bold" data-testid="total-users">{stats.total_users}</p>
                    </div>
                    <Users className="h-8 w-8 text-blue-200" />
                  </div>
                </CardContent>
              </Card>
              
              <Card className="bg-gradient-to-r from-green-500 to-green-600 text-white">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-green-100">Total Stores</p>
                      <p className="text-3xl font-bold" data-testid="total-stores">{stats.total_stores}</p>
                    </div>
                    <Store className="h-8 w-8 text-green-200" />
                  </div>
                </CardContent>
              </Card>
              
              <Card className="bg-gradient-to-r from-purple-500 to-purple-600 text-white">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-purple-100">Total Ratings</p>
                      <p className="text-3xl font-bold" data-testid="total-ratings">{stats.total_ratings}</p>
                    </div>
                    <TrendingUp className="h-8 w-8 text-purple-200" />
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="users">
            <Card>
              <CardHeader>
                <CardTitle>User Management</CardTitle>
                <CardDescription>Manage all users in the system</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {users.map((user) => (
                    <div key={user.id} className="flex items-center justify-between p-4 border rounded-lg">
                      <div className="flex items-center space-x-4">
                        <div className="bg-blue-100 p-2 rounded-full">
                          <User className="h-5 w-5 text-blue-600" />
                        </div>
                        <div>
                          <h3 className="font-semibold">{user.name}</h3>
                          <p className="text-sm text-gray-600 flex items-center">
                            <Mail className="h-4 w-4 mr-1" />
                            {user.email}
                          </p>
                          <p className="text-sm text-gray-600 flex items-center">
                            <MapPin className="h-4 w-4 mr-1" />
                            {user.address}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Badge variant="secondary">
                          {user.role.replace('_', ' ').toUpperCase()}
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="stores">
            <Card>
              <CardHeader>
                <CardTitle>Store Management</CardTitle>
                <CardDescription>Manage store approvals and listings</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {stores.map((store) => (
                    <div key={store.id} className="flex items-center justify-between p-4 border rounded-lg">
                      <div className="flex items-center space-x-4">
                        <div className="bg-green-100 p-2 rounded-full">
                          <Store className="h-5 w-5 text-green-600" />
                        </div>
                        <div>
                          <h3 className="font-semibold">{store.name}</h3>
                          <p className="text-sm text-gray-600 flex items-center">
                            <Mail className="h-4 w-4 mr-1" />
                            {store.email}
                          </p>
                          <p className="text-sm text-gray-600 flex items-center">
                            <MapPin className="h-4 w-4 mr-1" />
                            {store.address}
                          </p>
                          <div className="flex items-center mt-2">
                            <Star className="h-4 w-4 text-yellow-500 mr-1" />
                            <span className="text-sm">{store.average_rating.toFixed(1)} ({store.total_ratings} ratings)</span>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        {getStatusBadge(store.status)}
                        {store.status === 'pending' && (
                          <div className="flex space-x-2">
                            <Button 
                              size="sm" 
                              className="bg-green-600 hover:bg-green-700"
                              onClick={() => approveStore(store.id)}
                              data-testid={`approve-store-${store.id}`}
                            >
                              <Check className="h-4 w-4" />
                            </Button>
                            <Button 
                              size="sm" 
                              variant="destructive"
                              onClick={() => rejectStore(store.id)}
                              data-testid={`reject-store-${store.id}`}
                            >
                              <X className="h-4 w-4" />
                            </Button>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

// Normal User Dashboard
const UserDashboard = () => {
  const [stores, setStores] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [userRatings, setUserRatings] = useState({});

  useEffect(() => {
    fetchStores();
  }, []);

  const fetchStores = async () => {
    try {
      const response = await axios.get(`${API}/stores`);
      setStores(response.data);
      
      // Fetch user's ratings for each store
      const ratings = {};
      for (const store of response.data) {
        try {
          const ratingRes = await axios.get(`${API}/ratings/my-rating/${store.id}`);
          ratings[store.id] = ratingRes.data.rating;
        } catch (error) {
          ratings[store.id] = null;
        }
      }
      setUserRatings(ratings);
    } catch (error) {
      toast.error('Failed to fetch stores');
    }
    setLoading(false);
  };

  const submitRating = async (storeId, rating) => {
    try {
      await axios.post(`${API}/ratings`, {
        store_id: storeId,
        rating: rating
      });
      toast.success('Rating submitted successfully');
      
      // Update local state
      setUserRatings(prev => ({ ...prev, [storeId]: rating }));
      
      // Refresh stores to get updated average rating
      fetchStores();
    } catch (error) {
      toast.error('Failed to submit rating');
    }
  };

  const renderStars = (rating, onStarClick = null, readonly = false) => {
    return (
      <div className="flex">
        {[1, 2, 3, 4, 5].map((star) => (
          <Star
            key={star}
            className={`h-5 w-5 ${
              star <= rating ? 'text-yellow-500 fill-current' : 'text-gray-300'
            } ${!readonly ? 'cursor-pointer hover:text-yellow-400' : ''}`}
            onClick={() => !readonly && onStarClick && onStarClick(star)}
          />
        ))}
      </div>
    );
  };

  const filteredStores = stores.filter(store =>
    store.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    store.address.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <h1 className="text-3xl font-bold text-gray-900" data-testid="user-dashboard-title">Store Directory</h1>
        </div>
      </div>
      
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-6">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-5 w-5" />
            <Input
              placeholder="Search stores by name or address..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10 h-12"
              data-testid="store-search"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredStores.map((store) => (
            <Card key={store.id} className="hover:shadow-lg transition-shadow">
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <span>{store.name}</span>
                  <div className="flex items-center">
                    <Star className="h-4 w-4 text-yellow-500 mr-1" />
                    <span className="text-sm">{store.average_rating.toFixed(1)}</span>
                  </div>
                </CardTitle>
                <CardDescription>
                  <div className="flex items-center">
                    <MapPin className="h-4 w-4 mr-1" />
                    {store.address}
                  </div>
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div>
                    <p className="text-sm font-medium mb-2">Store Rating:</p>
                    {renderStars(store.average_rating, null, true)}
                    <p className="text-xs text-gray-500 mt-1">{store.total_ratings} ratings</p>
                  </div>
                  
                  <div>
                    <p className="text-sm font-medium mb-2">
                      Your Rating:
                      {userRatings[store.id] && (
                        <span className="ml-2 text-blue-600">({userRatings[store.id]} stars)</span>
                      )}
                    </p>
                    {renderStars(
                      userRatings[store.id] || 0, 
                      (rating) => submitRating(store.id, rating)
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {filteredStores.length === 0 && (
          <div className="text-center py-12">
            <Store className="h-16 w-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">No stores found</h3>
            <p className="text-gray-600">Try adjusting your search criteria</p>
          </div>
        )}
      </div>
    </div>
  );
};

// Header Component
const Header = () => {
  const { user, logout } = useAuth();

  return (
    <header className="bg-white shadow-sm border-b">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center py-4">
          <div className="flex items-center">
            <h2 className="text-xl font-semibold text-gray-800">
              Welcome, {user?.name}
            </h2>
            <Badge variant="secondary" className="ml-3">
              {user?.role?.replace('_', ' ').toUpperCase()}
            </Badge>
          </div>
          <Button 
            onClick={logout} 
            variant="outline"
            className="flex items-center space-x-2"
            data-testid="logout-button"
          >
            <LogOut className="h-4 w-4" />
            <span>Logout</span>
          </Button>
        </div>
      </div>
    </header>
  );
};

// Protected Route Component
const ProtectedRoute = ({ children, allowedRoles }) => {
  const { user, token, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (!token || !user) {
    return <Navigate to="/login" replace />;
  }

  if (allowedRoles && !allowedRoles.includes(user.role)) {
    return <Navigate to="/unauthorized" replace />;
  }

  return (
    <>
      <Header />
      {children}
    </>
  );
};

// Main App Component
function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <div className="App">
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            
            <Route path="/admin" element={
              <ProtectedRoute allowedRoles={['system_admin']}>
                <AdminDashboard />
              </ProtectedRoute>
            } />
            
            <Route path="/dashboard" element={
              <ProtectedRoute allowedRoles={['normal_user']}>
                <UserDashboard />
              </ProtectedRoute>
            } />
            
            <Route path="/unauthorized" element={
              <div className="min-h-screen flex items-center justify-center bg-red-50">
                <Card className="max-w-md">
                  <CardContent className="text-center p-6">
                    <AlertCircle className="h-16 w-16 text-red-500 mx-auto mb-4" />
                    <h2 className="text-2xl font-bold text-red-700 mb-2">Access Denied</h2>
                    <p className="text-red-600">You don't have permission to access this page.</p>
                  </CardContent>
                </Card>
              </div>
            } />
            
            <Route path="/" element={
              <Navigate to={
                localStorage.getItem('token') ? '/dashboard' : '/login'
              } replace />
            } />
          </Routes>
          
          <Toaster position="top-right" richColors />
        </div>
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;