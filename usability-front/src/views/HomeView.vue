<!-- eslint-disable no-unused-vars -->
<template>
  <!-- fragmento de codigo que muestra  bienvenida en la página web -->
  <div>
    <div class="containers">
      <img src="../assets/lading/imagen2.png" alt="WhatsApp" >
      <div class="t1">
        <h1>Bienvenido a Heuristicas App</h1> 
      </div>
     
      <p>Mejora la experiencia de usuario de tu sitio web mediante nuestras pruebas heurísticas.</p>
      <a href="#features" class="btn-primary">Descubre más</a>
    </div>
     <div id="features" class="t1">
      <h2>experimenta con nosotros</h2>
      <div class="features">
        <!-- agregar las características de tu sistema de usabilidad -->
        <!-- fragmento de codigo se encarga de mostar subtítulos,un párrafo e imagenes -->
        <div class="feature">
          <img src="../assets/lading/checklist.gif" alt="Pruebas Heurísticas">
          <h3>Pruebas Heurísticas</h3>
          <p>Empleamos técnicas heurísticas para detectar posibles obstáculos en la usabilidad y así perfeccionar la experiencia del usuario.</p>
        </div>
        <div class="feature">
          <img src="../assets/lading/testingusuario.gif" alt="Testing de Usuario">
          <h3>Testing de Usuario</h3>
          <p>Llevamos a cabo tests con usuarios para recibir comentarios directos y optimizar la usabilidad de tu página web.</p>
        </div>
        <div class="feature">
          <img src="../assets/lading/analisisdatos.gif" alt="Análisis de Datos">
          <h3>Análisis de Datos</h3>
          <p>Análisis de los resultados de la evalución obtenidos para comprender el comportamiento del usuario y tomar decisiones informadas para mejorar la usabilidad.</p>
        </div>
      </div>
    </div>
<!-- fragmento de código nos muestra un subtítulo,párrafo y un formulario -->
    <div class="info" >
      
        <h3>Contacto</h3>

      <p>¿Interesado en nuestro sistema de usabilidad? Contáctanos para obtener más información.</p>
      <form calss="contact">
            <label for="nombre">Nombre :</label>
            <input type="text" id="Nombre" name="Nombre" placeholder="escriba aquí su nombre" required>
            <label for="email">Email :</label>
            <input type="mail" id="email" name="email" placeholder="escriba aquí su email" required>
            <label for="mensaje">Mensaje :</label>
            <textarea name="message" placeholder="escriba aquí su mensaje" required></textarea>
            <br>
            <br>
            <button type="submit" class="btn-button">Enviar</button>
            </form>
    </div>
  </div>
  <!-- pie de página-->
  <footer class="footer">
  <!-- fragmento de código para mostrar redes sociales y dirigir a cada una de ellas -->
  <div class="social-container">
    <div class="social-icons">
      <a href="https://www.facebook.com/" target="_blank" class="social-link">
        <img src="../assets/lading/facebook.png" alt="Facebook">
      </a>
      <a href="https://www.instagram.com/" target="_blank" class="social-link">
        <img src="../assets/lading/instagram.jpg" alt="Instagram">
      </a>
      <a href="https://wa.me/" target="_blank" class="social-link">
        <img src="../assets/lading/whatsapp.jpg" alt="WhatsApp">
      </a>
    </div>
  </div>
  <p>derechos reservados &copy; 2024 / Centro de Desarrollo Tecnológico Creatic</p>
</footer>

</template>

<style scoped>



body {
   font-family: 'Poppins', sans-serif;
   margin: 0;
   padding: 0;
 
}

.containers {
   text-align: center;
   padding: 50px 20px;
}
.info {
   text-align: center;
   padding: 50px 20px;
   color: #352480;
}
.t1{
  text-align: center;
  background-color: #352480;
}
h1 {
   color: #f1ecec;
   font-size: 2.5rem;
   margin-bottom: 20px;
}
h2 {
   color: #f1ecec;
   font-size: 2.5rem;
   margin-bottom: 20px;
}

h3 {
   color: #070707;
   font-size: 2.5rem;
   margin-bottom: 20px;
}
h4 {
   color: #352480;
   font-size: 2.5rem;
   margin-bottom: 20px;
}
p {
   color: #328867;
   font-size: 1.2rem;
   line-height: 1.6;
}

.btn-button {
     background-color: #517569; 
    color: #fff; 
    padding: 10px 20px; 
    margin-top: 10px; 
    border: none;
    border-radius: 5px; 
    cursor: pointer;
  }
  .features {
    margin-top: 50px;
    display: flex;
    justify-content: center;
  }

  
  .feature {
    flex: 0 1 30%;
    padding: 20px;
  }

  /* Estilos para cambiar el color de fondo del texto cuando se coloca el puntero encima */
  .feature:hover {
    background-color: #f0f0f0; 
  }
.feature img {
   max-width: 100%;
   height: auto;
}
.footer {
  background-color: #352480;
  color: #fff;
  padding: 0px 0;
  text-align: center;
}
.social-container {
    display: flex; 
    justify-content: flex-start; 
    align-items: center; 
    margin-top: 20px;
    margin-left: 20px; 
  }
  .social-link {
    display: inline-block;
    margin-right: 10px; 
  }
  .social-link img {
    width: 40px;
    height: auto;
  }

</style>