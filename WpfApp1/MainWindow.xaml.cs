using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace WpfApp1;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    // Поле класса (аналог private переменной в C++)
    private int clickCount = 0;
        
    public MainWindow()
    {
        InitializeComponent();
        // Создание кнопки
        Button myButton = new Button();
        myButton.Content = "Нажми меня";
            
        // ПОДПИСКА НА СОБЫТИЕ - самая важная часть!
        // "+=" - добавляем обработчик к событию Click
        // Аналог в C++: button->addClickListener(this);
        // Аналог в Python: button.on_click = self.button_click
        myButton.Click += Button_Click;
            
        this.Content = myButton;
    }
        
    // ОБРАБОТЧИК СОБЫТИЯ
    private void Button_Click(object sender, RoutedEventArgs e)
    {
        // 1. Приведение типов (аналог static_cast в C++)
        Button clickedButton = (Button)sender;
            
        // 2. Использование параметров
        clickCount++;
            
        // 3. Работа с объектом, вызвавшим событие
        clickedButton.Content = $"Нажато: {clickCount} раз";
            
        // 4. Использование данных события
        string eventInfo = $"Время: {DateTime.Now}";
            
        MessageBox.Show(eventInfo);
    }
}